import copy
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from contextlib import ExitStack
from pathlib import Path
from unittest.mock import patch

import aieos_followups as af
import server


def record():
    r = dict(source_system="AIEOS", mode="FOLLOWUP", source_lead_id="source",
             followup_id="followup", original_gmail_thread_id="thread", message_version="V2",
             followup_type="CORRECTION", recipient="qa@example.com",
             subject="New correction subject", body="Dear QA,\n\n" + "approved content " * 70 + "— End")
    for k in ("recipient", "subject", "body"):
        r[k + "_hash"] = af.digest(r[k])
    r["manifest"] = {k: r[k] for k in ("source_system", "mode", *af.IDENTITY)}
    r["signature"] = hmac.new(b"test-secret", json.dumps(r["manifest"], ensure_ascii=False,
        sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    return r


class FakeGmail:
    def __init__(self):
        self.calls = []
    def send_email(self, **kw):
        self.calls.append(kw)
        return {"message_id": "gmail-one", "thread_id": "thread"}


class FollowupTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        tmp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.ledger = str(Path(tmp) / "ledger.sqlite3")
        self.stack.enter_context(patch.dict(os.environ, {"AIEOS_HANDOFF_HMAC_SECRET": "test-secret", "AIEOS_OPERATOR_API_KEY": "test-operator"}))
        self.stack.enter_context(patch.object(server, "FOLLOWUP_DELIVERY_DB", self.ledger))
        self.stack.enter_context(patch.object(server, "_kill_switch_on", return_value=False))
        self.stack.enter_context(patch.object(server, "_send_count_today", return_value=0))
        self.stack.enter_context(patch.object(server, "_bump_send_count"))
        self.stack.enter_context(patch.object(server, "_is_dnc", return_value=False))
        self.stack.enter_context(patch.object(server, "SEND_DELAY_SECONDS", 0))
        self.lead = dict(id="oq", name="QA", status="sent", contact_email="qa@example.com",
                         gmail_thread_id="thread", gmail_message_id="initial-message",
                         first_outreach_sent=True, follow_up_body="")
        self.prospects = [self.lead]
        self.stack.enter_context(patch.object(server, "_load", side_effect=lambda: self.prospects))
        self.stack.enter_context(patch.object(server, "_save"))
        self.client = server.app.test_client()
        self.inbox = str(Path(tmp) / "followup_written.json")
        self.stack.enter_context(patch.object(server, "FOLLOWUP_WRITTEN_JSON", self.inbox))
        self.gmail = FakeGmail()

    def imported(self):
        r = record()
        self.assertTrue(af.import_record(self.prospects, self.lead, r, self.ledger))
        return self.lead["aieos_followups"][0]

    def approved(self):
        self.imported()
        return af.approve(self.lead, "followup", self.ledger, "test-operator")

    def run_sender(self):
        with server.app.app_context():
            return server._run_signed_followups(self.gmail, self.prospects, "test-operator")

    def test_import_review_approval_and_signature(self):
        Path(self.inbox).write_text(json.dumps([{"id": "oq", **record()}]), encoding="utf-8")
        response = self.client.post("/api/email/import-followups")
        self.assertEqual(response.status_code, 200, response.get_json())
        # _save is intercepted; inspect import helpers for persistence semantics separately.
        r = self.imported()
        self.assertEqual(r["review_status"], "PENDING_REVIEW")
        self.assertEqual(r["status"], "drafted")
        review = self.client.get("/api/email/followups/review").get_json()
        self.assertEqual(len(review["items"]), 1)
        response = self.client.post("/api/email/followups/approve",
                                    json={"id": "oq", "followup_id": "followup"},
                                    headers={"X-AIEOS-Operator-Key": "test-operator"})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(server.validate_aieos_frozen_handoff(self.lead, r, operation="followup"))

    def test_frozen_send_and_duplicate_after_reimport(self):
        r = self.approved()
        original = copy.deepcopy(self.lead)
        count, results = self.run_sender()
        self.assertEqual(count, 1)
        self.assertEqual(self.gmail.calls, [{"to": r["recipient"], "subject": r["subject"],
                          "body_text": r["body"], "thread_id": "thread"}])
        for field in ("status", "gmail_thread_id", "gmail_message_id", "first_outreach_sent"):
            self.assertEqual(self.lead[field], original[field])
        self.assertEqual(r["review_status"], "Used")
        self.assertEqual(self.run_sender()[0], 0)
        self.assertEqual(len(self.gmail.calls), 1)
        with self.assertRaises(ValueError):
            af.import_record(self.prospects, self.lead, record(), self.ledger)
        # Recreate a different id/body for the same source version: ledger still denies it.
        r2 = record()
        r2["followup_id"] = "another"
        self.assertTrue(af.delivery_exists(self.ledger, r2))

    def test_each_tamper_has_zero_gmail_and_no_tracking(self):
        for field in ("mode", "source_system", "recipient", "subject", "body", "original_gmail_thread_id",
                      "message_version", "followup_id", "source_lead_id", "followup_type",
                      "recipient_hash", "subject_hash", "body_hash"):
            with self.subTest(field=field):
                self.lead.pop("aieos_followups", None)
                r = self.approved()
                r[field] = "tampered"
                before = copy.deepcopy(self.lead)
                self.assertEqual(self.run_sender()[0], 0)
                self.assertEqual(self.gmail.calls, [])
                self.assertEqual(self.lead, before)
                self.assertFalse(Path(self.ledger).exists())

    def test_missing_signature_missing_approval_and_thread_change(self):
        r = self.imported()
        self.assertEqual(self.run_sender()[0], 0)
        r = af.approve(self.lead, "followup", self.ledger, "test-operator")
        signature = r.pop("signature")
        self.assertEqual(self.run_sender()[0], 0)
        r["signature"] = signature
        self.lead["gmail_thread_id"] = "changed"
        self.assertEqual(self.run_sender()[0], 0)
        self.assertEqual(self.gmail.calls, [])

    def test_correction_exemption_does_not_change_global_policy(self):
        self.assertTrue(server._followup_block_reasons(record()["body"]))
        self.approved()
        self.assertEqual(self.run_sender()[0], 1)
        self.assertTrue(server._followup_block_reasons(record()["body"]))

    def test_signed_standard_still_uses_global_policy(self):
        r = record()
        r["followup_type"] = "STANDARD"
        r["manifest"]["followup_type"] = "STANDARD"
        r["signature"] = hmac.new(b"test-secret",json.dumps(r["manifest"],ensure_ascii=False,
            sort_keys=True,separators=(",",":")).encode(),hashlib.sha256).hexdigest()
        af.import_record(self.prospects,self.lead,r,self.ledger)
        af.approve(self.lead,"followup",self.ledger,"test-operator")
        self.assertEqual(self.run_sender()[0],0)
        self.assertEqual(self.gmail.calls,[])

    def test_failed_gmail_reservation_never_retries(self):
        self.approved()
        with patch.object(self.gmail, "send_email", side_effect=RuntimeError("uncertain")) as send:
            self.assertEqual(self.run_sender()[0], 0)
            self.assertEqual(send.call_count, 1)
            self.assertEqual(self.run_sender()[0], 0)
            self.assertEqual(send.call_count, 1)
        self.assertEqual(self.lead["status"], "sent")
        self.assertEqual(self.lead["aieos_followups"][0]["review_status"], "RECONCILIATION_REQUIRED")

    def test_gate_cannot_mutate_frozen_send_payload(self):
        r = self.approved()
        def gate(_email):
            r["body"] = "mutated stored body during gate"
            return False
        with patch.object(server, "_is_dnc", side_effect=gate):
            self.assertEqual(self.run_sender()[0], 0)
        self.assertEqual(self.gmail.calls, [])

    def test_version_collision_with_another_id_rejected_before_send(self):
        self.imported()
        r = record()
        r["followup_id"] = "different"
        r["manifest"]["followup_id"] = "different"
        r["signature"] = hmac.new(b"test-secret", json.dumps(r["manifest"], ensure_ascii=False,
            sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        with self.assertRaisesRegex(ValueError, "VERSION_EXISTS"):
            af.import_record(self.prospects, self.lead, r, self.ledger)
        self.assertEqual(self.gmail.calls, [])

    def test_non_aieos_legacy_body_and_subject_preserved(self):
        self.lead.update(follow_up_body="A useful update.", outreach_subject="Original")
        with patch.object(server, "_update_email_log_status"), patch.object(server,"EMAIL_SIGNATURE","Signature"), server.app.app_context():
            result = server._run_send_followups(self.gmail).get_json()
        self.assertEqual(result["sent"], 1)
        self.assertEqual(self.gmail.calls[0], dict(to="qa@example.com",subject="Re: Original",
                         body_text="A useful update.\n\nSignature",thread_id="thread"))

    def test_operator_auth_failures_do_not_touch_state_or_gmail(self):
        from mailer import gmail_client
        r = self.imported()
        for key in (None, "", "wrong", True):
            for endpoint in ("/api/email/followups/approve", "/api/email/send-followups"):
                with self.subTest(key=key, endpoint=endpoint):
                    before = copy.deepcopy(self.prospects)
                    headers = {} if key is None else {"X-AIEOS-Operator-Key": str(key)}
                    with patch.object(gmail_client, "send_email") as send, patch.object(
                            gmail_client, "is_configured") as configured, patch.object(
                            server, "_set_send_in_progress") as tracking:
                        response = self.client.post(endpoint, headers=headers, json={
                            "id": "oq", "followup_id": "followup", "approved": True,
                            "status": "Approved", "confirmed": True})
                    self.assertEqual(response.status_code, 403)
                    send.assert_not_called()
                    configured.assert_not_called()
                    tracking.assert_not_called()
                    server._save.assert_not_called()
                    server._bump_send_count.assert_not_called()
                    self.assertEqual(self.prospects, before)
                    self.assertFalse(Path(self.ledger).exists())
        for key in (None, "wrong", True):
            with self.assertRaises(ValueError):
                af.approve(self.lead, "followup", self.ledger, key)
            before = copy.deepcopy(self.prospects)
            self.assertEqual(server._run_signed_followups(self.gmail, self.prospects, key)[0], 0)
            with server.app.app_context():
                self.assertEqual(server._run_send_followups(self.gmail, key)[1], 403)
            self.assertEqual(self.prospects, before)
        self.assertEqual(self.gmail.calls, [])

    def test_valid_authenticated_api_path_fake_gmail_only(self):
        from mailer import gmail_client
        r = self.imported()
        headers = {"X-AIEOS-Operator-Key": "test-operator"}
        response = self.client.post("/api/email/followups/approve", headers=headers,
                                   json={"id": "oq", "followup_id": "followup"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(r["status"], "Approved")
        with patch.object(gmail_client, "is_configured", return_value=True), patch.object(
                gmail_client, "send_email", side_effect=self.gmail.send_email), patch.object(
                server, "_send_in_progress", return_value=False), patch.object(
                server, "_set_send_in_progress"):
            response = self.client.post("/api/email/send-followups", headers=headers, json={})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["sent"], 1)
        self.assertEqual(len(self.gmail.calls), 1)
        self.assertEqual(self.lead["status"], "sent")
        self.assertTrue(self.lead["first_outreach_sent"])

    def test_forged_stored_approval_and_revoked_key_fail_closed(self):
        r = self.imported()
        r.update(status="Approved", review_status="Approved", approved_at="forged",
                 approved_signature=r["signature"], operator_approval_proof="forged")
        before = copy.deepcopy(self.prospects)
        self.assertEqual(self.run_sender()[0], 0)
        self.assertEqual(self.prospects, before)
        r["review_status"] = "PENDING_REVIEW"
        af.approve(self.lead, "followup", self.ledger, "test-operator")
        before = copy.deepcopy(self.prospects)
        for value in ("", "rotated-key"):
            with patch.dict(os.environ, {"AIEOS_OPERATOR_API_KEY": value}):
                self.assertEqual(self.run_sender()[0], 0)
                self.assertEqual(server._run_signed_followups(
                    self.gmail, self.prospects, value)[0], 0)
        self.assertEqual(self.prospects, before)
        self.assertEqual(self.gmail.calls, [])
        server._save.assert_not_called()
        server._bump_send_count.assert_not_called()
        self.assertFalse(Path(self.ledger).exists())

    def test_import_tampering_does_not_save(self):
        r=record(); r["body"]="changed"
        Path(self.inbox).write_text(json.dumps([{"id":"oq",**r}]),encoding="utf-8")
        with patch.object(server,"_save") as save:
            response=self.client.post("/api/email/import-followups")
        self.assertEqual(response.status_code,409)
        save.assert_not_called()
        self.assertEqual(self.gmail.calls,[])

if __name__ == "__main__":
    unittest.main()

