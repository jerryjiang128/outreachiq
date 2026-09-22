import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


def _lead(*, variants=True):
    return {
        "id": "lead-1",
        "name": "Example Co",
        "status": "drafted",
        "contact_email": "buyer@example.test",
        "outreach_subject": "Legacy subject",
        "outreach_draft": "Legacy body",
        "email_variants": [
            {"label": "A", "approach": "observation", "subject": "Subject A", "body": "Body A"},
            {"label": "B", "approach": "peer", "subject": "Subject B", "body": "Body B"},
        ] if variants else [],
    }


class _FakeGmail:
    def __init__(self):
        self.calls = []

    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        return {"message_id": "fake", "thread_id": "fake"}


class InitialApproveTests(unittest.TestCase):
    def setUp(self):
        # Register environment cleanup before importing config (dotenv may change it).
        self.enterContext(patch.dict(os.environ, {}, clear=False))
        import server

        self.server = server
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.prospects = root / "prospects.json"
        self.prospects.write_text(json.dumps([_lead()]), encoding="utf-8")
        self.patches = [
            patch.object(server, "PROSPECTS_JSON", str(self.prospects)),
            patch.object(server, "DATA_DIR", str(root / "data")),
            patch.object(server, "BACKUPS_DIR", str(root / "backups")),
            patch.dict(os.environ, {
                "OUTREACHIQ_WEB_BRIDGE_KEY": "bridge-test-secret",
                "OUTREACHIQ_WEB_BRIDGE_ALLOWED_NETWORKS": "127.0.0.1/32",
            }, clear=False),
        ]
        for item in self.patches:
            self.enterContext(item)
        self.enterContext(patch.dict(server.app.config, {"TESTING": True}))
        self.client = server.app.test_client()

    @staticmethod
    def bridge_headers():
        return {
            "X-OutreachIQ-Bridge-Key": "bridge-test-secret",
            "X-OutreachIQ-Approved-By": "web-operator",
        }

    def _detail(self, lead_id="lead-1"):
        return self.client.get(
            f"/api/internal/initial-review/{lead_id}",
            headers={"X-OutreachIQ-Bridge-Key": "bridge-test-secret"},
        )

    def _saved(self):
        return json.loads(self.prospects.read_text(encoding="utf-8"))[0]

    def test_legacy_approve_preserves_send_prepared_and_legacy_response(self):
        response = self.client.post("/api/email/approve", json={"id": "lead-1", "variant_index": 1})
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertTrue(payload["approved"])
        self.assertEqual(payload["lead"]["approved_variant"], 1)
        self.assertEqual(payload["lead"]["approved_by"], "legacy-api")
        self.assertTrue(payload["lead"]["approved_for_send"])
        self.assertEqual(payload["lead"]["last_send_variant_index"], 1)
        self.assertEqual(payload["lead"]["last_send_variant_label"], "B")
        self.assertEqual(payload["lead"]["last_send_channel"], "gmail")
        saved = self._saved()
        self.assertTrue(saved["last_send_prepared_at"])
        self.assertTrue(saved["approved_at"])
        self.assertTrue(saved["approved_for_send"])
        self.assertEqual(self.server._approved_index(saved), 1)
        self.assertTrue(self.server._approved_for_send(saved))

    def test_bridge_auth_and_network_fail_closed(self):
        old_key = os.environ.pop("OUTREACHIQ_WEB_BRIDGE_KEY")
        try:
            self.assertEqual(self._detail().status_code, 403)
        finally:
            os.environ["OUTREACHIQ_WEB_BRIDGE_KEY"] = old_key
        self.assertEqual(self.client.get(
            "/api/internal/initial-review/lead-1",
            headers={"X-OutreachIQ-Bridge-Key": "wrong"},
        ).status_code, 403)

        old_network = os.environ.pop("OUTREACHIQ_WEB_BRIDGE_ALLOWED_NETWORKS")
        try:
            self.assertEqual(self._detail().status_code, 403)
        finally:
            os.environ["OUTREACHIQ_WEB_BRIDGE_ALLOWED_NETWORKS"] = old_network
        os.environ["OUTREACHIQ_WEB_BRIDGE_ALLOWED_NETWORKS"] = "not-a-network"
        try:
            self.assertEqual(self._detail().status_code, 403)
        finally:
            os.environ["OUTREACHIQ_WEB_BRIDGE_ALLOWED_NETWORKS"] = old_network

    def test_bridge_network_rejects_outside_remote_and_forwarded_header(self):
        headers = {**self.bridge_headers(), "X-Forwarded-For": "127.0.0.1"}
        response = self.client.get(
            "/api/internal/initial-review/lead-1",
            headers=headers,
            environ_base={"REMOTE_ADDR": "192.0.2.1"},
        )
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._detail().status_code, 200)

    def test_bridge_detail_normalizes_authoritative_variants_and_fingerprints(self):
        response = self._detail()
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIsNone(payload["message_version"])
        self.assertEqual(payload["variants"][1]["body"], "Body B")
        self.assertEqual(payload["variants"][0]["variant_index"], 0)
        self.assertEqual(len(payload["variants"][0]["review_fingerprint"]), 64)
        self.assertNotEqual(
            payload["variants"][0]["review_fingerprint"],
            payload["variants"][1]["review_fingerprint"],
        )

    def test_bridge_detail_normalizes_legacy_single_draft(self):
        self.prospects.write_text(json.dumps([_lead(variants=False)]), encoding="utf-8")
        response = self._detail()
        self.assertEqual(response.status_code, 200)
        variant = response.get_json()["variants"]
        self.assertEqual(variant[0]["variant_index"], 0)
        self.assertEqual(variant[0]["label"], "single")
        self.assertEqual(variant[0]["subject"], "Legacy subject")
        self.assertEqual(variant[0]["body"], "Legacy body")
        self.assertEqual(len(variant[0]["review_fingerprint"]), 64)

    def test_bridge_approve_is_approval_only_and_uses_server_identity(self):
        fingerprint = self._detail().get_json()["variants"][1]["review_fingerprint"]
        with patch.object(self.server, "_record_send_prepared") as prepared, \
                patch.object(self.server, "_run_send_approved", side_effect=AssertionError("send must not run")):
            response = self.client.post(
                "/api/internal/initial-review/lead-1/approve",
                json={"variant_index": 1, "review_fingerprint": fingerprint},
                headers=self.bridge_headers(),
            )
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload["approval_state"], "APPROVED")
        self.assertEqual(payload["approved_variant"], 1)
        self.assertTrue(payload["approved_at"])
        self.assertEqual(payload["approved_by"], "web-operator")
        self.assertIs(payload["message_version"], None)
        prepared.assert_not_called()
        saved = self._saved()
        self.assertFalse(saved["approved_for_send"])
        self.assertEqual(saved["approved_by"], "web-operator")
        for field in (
            "last_send_prepared_at", "last_send_channel", "last_send_variant_index",
            "last_send_variant_label", "last_send_variant_approach", "last_send_subject",
        ):
            self.assertIn(saved.get(field), (None, ""))

    def test_web_approved_variant_is_excluded_from_send_queue(self):
        fingerprint = self._detail().get_json()["variants"][0]["review_fingerprint"]
        response = self.client.post(
            "/api/internal/initial-review/lead-1/approve",
            json={"variant_index": 0, "review_fingerprint": fingerprint},
            headers=self.bridge_headers(),
        )
        self.assertEqual(response.status_code, 200)
        fake = _FakeGmail()
        with self.server.app.app_context(), \
                patch.object(self.server, "_load_dnc", return_value={}), \
                patch.object(self.server, "_send_count_today", return_value=0), \
                patch.object(self.server, "_kill_switch_on", return_value=False):
            result = self.server._run_send_approved(fake, None).get_json()
        self.assertEqual(result["sent"], 0)
        self.assertEqual(fake.calls, [])
        self.assertEqual(self.client.get("/api/email/approved-count").get_json()["count"], 0)

    def test_historical_missing_approved_for_send_remains_eligible(self):
        historical = _lead()
        historical["approved_variant"] = 0
        self.prospects.write_text(json.dumps([historical]), encoding="utf-8")
        loaded = self._saved()
        self.assertNotIn("approved_for_send", loaded)
        ensured = self.server._ensure_fields(loaded)
        self.assertTrue(self.server._approved_for_send(ensured))

    def test_unapprove_clears_approval_send_eligibility_and_identity(self):
        self.assertEqual(self.client.post(
            "/api/email/approve", json={"id": "lead-1", "variant_index": 0}
        ).status_code, 200)
        response = self.client.post("/api/email/approve", json={"id": "lead-1", "unapprove": True})
        self.assertEqual(response.status_code, 200)
        saved = self._saved()
        self.assertIsNone(saved["approved_variant"])
        self.assertIsNone(saved["approved_at"])
        self.assertIsNone(saved["approved_by"])
        self.assertIsNone(saved["approved_for_send"])
        self.assertFalse(self.server._approved_for_send(saved))

    def test_bridge_rejects_client_content_identity_bad_variant_and_malformed_json(self):
        headers = self.bridge_headers()
        fingerprint = self._detail().get_json()["variants"][0]["review_fingerprint"]
        forged = {
            "variant_index": 0, "review_fingerprint": fingerprint,
            "recipient": "attacker@example.test", "body": "forged", "approved_by": "attacker",
        }
        self.assertEqual(self.client.post(
            "/api/internal/initial-review/lead-1/approve", json=forged, headers=headers
        ).status_code, 400)
        for bad_index in (9, True, 1.0, "1"):
            self.assertEqual(self.client.post(
                "/api/internal/initial-review/lead-1/approve",
                json={"variant_index": bad_index, "review_fingerprint": fingerprint}, headers=headers
            ).status_code, 400)
        self.assertEqual(self.client.post(
            "/api/internal/initial-review/lead-1/approve", json={"variant_index": 0}, headers=headers
        ).status_code, 400)
        self.assertEqual(self.client.post(
            "/api/internal/initial-review/lead-1/approve", data="{",
            content_type="application/json", headers=headers
        ).status_code, 400)
        self.assertEqual(self.client.post(
            "/api/email/approve", data="{", content_type="application/json"
        ).status_code, 400)
        self.assertEqual(self.client.post(
            "/api/internal/initial-review/missing/approve",
            json={"variant_index": 0, "review_fingerprint": fingerprint}, headers=headers
        ).status_code, 404)
        self.assertEqual(self.client.post(
            "/api/internal/initial-review/lead-1/approve",
            json={"variant_index": 0, "review_fingerprint": fingerprint},
            headers={"X-OutreachIQ-Bridge-Key": "bridge-test-secret"},
        ).status_code, 400)

    def test_stale_multi_variant_review_is_rejected_without_mutation(self):
        detail = self._detail().get_json()
        fingerprint = detail["variants"][1]["review_fingerprint"]
        current = self._saved()
        current["email_variants"][1]["body"] = "Changed authoritative body"
        self.prospects.write_text(json.dumps([current]), encoding="utf-8")
        stale = self.client.post(
            "/api/internal/initial-review/lead-1/approve",
            json={"variant_index": 1, "review_fingerprint": fingerprint},
            headers=self.bridge_headers(),
        )
        self.assertEqual(stale.status_code, 409)
        after = self._saved()
        self.assertIsNone(after.get("approved_variant"))
        self.assertIsNone(after.get("approved_at"))
        self.assertIsNone(after.get("approved_by"))
        self.assertNotIn("last_send_prepared_at", after)

        fresh = self._detail().get_json()["variants"][1]["review_fingerprint"]
        accepted = self.client.post(
            "/api/internal/initial-review/lead-1/approve",
            json={"variant_index": 1, "review_fingerprint": fresh},
            headers=self.bridge_headers(),
        )
        self.assertEqual(accepted.status_code, 200)

    def test_variant_zero_approval_is_reported_as_approved(self):
        fingerprint = self._detail().get_json()["variants"][0]["review_fingerprint"]
        response = self.client.post(
            "/api/internal/initial-review/lead-1/approve",
            json={"variant_index": 0, "review_fingerprint": fingerprint},
            headers=self.bridge_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["approval_state"], "APPROVED")
        self.assertEqual(response.get_json()["approved_variant"], 0)

    def test_legacy_queue_is_revoked_by_web_approval(self):
        self.assertEqual(self.client.post(
            "/api/email/approve", json={"id": "lead-1", "variant_index": 0}
        ).status_code, 200)
        fingerprint = self._detail().get_json()["variants"][1]["review_fingerprint"]
        response = self.client.post(
            "/api/internal/initial-review/lead-1/approve",
            json={"variant_index": 1, "review_fingerprint": fingerprint},
            headers=self.bridge_headers(),
        )
        self.assertEqual(response.status_code, 200)
        self.assertFalse(self.server._approved_for_send(self._saved()))
        fake = _FakeGmail()
        with self.server.app.app_context(), \
                patch.object(self.server, "_load_dnc", return_value={}), \
                patch.object(self.server, "_send_count_today", return_value=0), \
                patch.object(self.server, "_kill_switch_on", return_value=False):
            result = self.server._run_send_approved(fake, None).get_json()
        self.assertEqual(result["sent"], 0)
        self.assertEqual(result["results"], [])
        self.assertEqual(fake.calls, [])

    def test_stale_recipient_subject_and_variant_order_do_not_write(self):
        for change in ("recipient", "subject", "order"):
            with self.subTest(change=change):
                self.prospects.write_text(json.dumps([_lead()]), encoding="utf-8")
                fingerprint = self._detail().get_json()["variants"][0]["review_fingerprint"]
                current = self._saved()
                if change == "recipient":
                    current["contact_email"] = "changed@example.test"
                elif change == "subject":
                    current["email_variants"][0]["subject"] = "Changed subject"
                else:
                    current["email_variants"].reverse()
                self.prospects.write_text(json.dumps([current]), encoding="utf-8")
                before = self.prospects.read_bytes()
                response = self.client.post(
                    "/api/internal/initial-review/lead-1/approve",
                    json={"variant_index": 0, "review_fingerprint": fingerprint},
                    headers=self.bridge_headers(),
                )
                self.assertEqual(response.status_code, 409)
                self.assertEqual(self.prospects.read_bytes(), before)

    def test_both_bridge_routes_require_network_and_key_without_writes(self):
        for remote in ("192.0.2.1", "", "invalid"):
            for method, suffix in (("GET", ""), ("POST", "/approve")):
                with self.subTest(remote=remote, method=method):
                    before = self.prospects.read_bytes()
                    response = self.client.open(
                        "/api/internal/initial-review/lead-1" + suffix,
                        method=method, json={"variant_index": 0},
                        headers={**self.bridge_headers(), "X-Forwarded-For": "127.0.0.1"},
                        environ_overrides={"REMOTE_ADDR": remote},
                    )
                    self.assertEqual(response.status_code, 403)
                    self.assertEqual(self.prospects.read_bytes(), before)
        with patch.dict(os.environ, {"OUTREACHIQ_WEB_BRIDGE_ALLOWED_NETWORKS": "::1/128"}):
            response = self.client.get(
                "/api/internal/initial-review/lead-1", headers=self.bridge_headers(),
                environ_overrides={"REMOTE_ADDR": "::1"},
            )
            self.assertEqual(response.status_code, 200)
        self.assertEqual(self.client.post(
            "/api/internal/initial-review/lead-1/approve", json={},
            headers={"X-OutreachIQ-Bridge-Key": "wrong"},
        ).status_code, 403)

    def test_invalid_json_shapes_and_null_multi_variant_do_not_write(self):
        for endpoint in ("/api/email/approve", "/api/internal/initial-review/lead-1/approve"):
            for body in ("{", "[]", "null", "42", '\"text\"'):
                with self.subTest(endpoint=endpoint, body=body):
                    before = self.prospects.read_bytes()
                    response = self.client.post(endpoint, data=body,
                        content_type="application/json", headers=self.bridge_headers())
                    self.assertEqual(response.status_code, 400)
                    self.assertEqual(self.prospects.read_bytes(), before)
        fingerprint = self._detail().get_json()["variants"][0]["review_fingerprint"]
        self.assertEqual(self.client.post(
            "/api/internal/initial-review/lead-1/approve",
            json={"variant_index": None, "review_fingerprint": fingerprint},
            headers=self.bridge_headers(),
        ).status_code, 400)
        self.assertEqual(self.client.post(
            "/api/email/approve", json={"id": 123}
        ).status_code, 400)

    def test_invalid_send_eligibility_fails_closed(self):
        for value in (False, 0, 1, "false", "true", [], {}):
            with self.subTest(value=value):
                self.assertFalse(self.server._approved_for_send({
                    "approved_variant": 0, "approved_for_send": value,
                }))

    def test_fixture_restores_testing_module_fields_and_environment(self):
        server = self.server
        fields = ("PROSPECTS_JSON", "DATA_DIR", "BACKUPS_DIR")
        before_fields = {name: getattr(server, name) for name in fields}
        before_env = dict(os.environ)
        before_config = dict(server.app.config)
        nested = InitialApproveTests("test_variant_zero_approval_is_reported_as_approved")
        try:
            nested.setUp()
            self.assertNotEqual(server.PROSPECTS_JSON, before_fields["PROSPECTS_JSON"])
        finally:
            nested.doCleanups()
        self.assertEqual({name: getattr(server, name) for name in fields}, before_fields)
        self.assertEqual(dict(os.environ), before_env)
        self.assertEqual(dict(server.app.config), before_config)

    def test_single_draft_fingerprint_is_stale_safe_and_legacy_ui_still_works(self):
        self.prospects.write_text(json.dumps([_lead(variants=False)]), encoding="utf-8")
        fingerprint = self._detail().get_json()["variants"][0]["review_fingerprint"]
        current = self._saved()
        current["outreach_draft"] = "Changed single draft"
        self.prospects.write_text(json.dumps([current]), encoding="utf-8")
        stale = self.client.post(
            "/api/internal/initial-review/lead-1/approve",
            json={"review_fingerprint": fingerprint}, headers=self.bridge_headers(),
        )
        self.assertEqual(stale.status_code, 409)
        legacy = self.client.post("/api/email/approve", json={"id": "lead-1"})
        self.assertEqual(legacy.status_code, 200)
        self.assertTrue(self._saved()["approved_for_send"])


if __name__ == "__main__":
    unittest.main()
