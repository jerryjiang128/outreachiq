import os
import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path
from unittest.mock import patch

import aieos_internal_test
from aieos_internal_test import InternalTestError


def _payload(**overrides):
    values = {
        "mode": "INTERNAL_TEST",
        "test_send_only": True,
        "source_lead_id": "laze",
        "message_version": "LAZE-INTERNAL-TEST-V1",
        "test_recipient": "jerryjiang128@gmail.com",
        "customer_recipient": "info@mimx.co.uk",
        "sender": "iris@ibeautytech.com",
        "subject": "Diode laser OEM & supply cooperation",
        "body": "Approved internal test body",
        "test_id": "test-id-1",
        "approval_status": "APPROVED",
        "approved_by": "Jerry",
    }
    values.update(overrides)
    manifest = {
        "source_system": "AIEOS",
        "mode": values["mode"],
        "test_send_only": values["test_send_only"],
        "approval_status": values["approval_status"],
        "approved_by_hash": aieos_internal_test.frozen_value_hash(values["approved_by"]),
        "source_lead_id": values["source_lead_id"],
        "message_version": values["message_version"],
        "test_id": values["test_id"],
        "sender_hash": aieos_internal_test.frozen_value_hash(values["sender"]),
        "test_recipient_hash": aieos_internal_test.frozen_value_hash(values["test_recipient"]),
        "customer_recipient_hash": aieos_internal_test.frozen_value_hash(values["customer_recipient"]),
        "frozen_subject_hash": aieos_internal_test.frozen_value_hash(values["subject"]),
        "frozen_body_hash": aieos_internal_test.frozen_value_hash(values["body"]),
    }
    values["aieos_internal_test_manifest"] = manifest
    values["aieos_internal_test_signature"] = aieos_internal_test._manifest_signature(manifest)
    return values


class _FakeGmail:
    def __init__(self):
        self.calls = []

    def is_configured(self):
        return True

    def is_sender_authorized(self, sender):
        return sender == "iris@ibeautytech.com"

    def send_email(self, **kwargs):
        self.calls.append(kwargs)
        return {"message_id": "gmail-internal-1", "thread_id": "thread-internal-1"}


class InternalTestDeliveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.ledger = Path(self.temp.name) / "internal.sqlite3"
        self.enterContext(patch.dict(os.environ, {
            "AIEOS_INTERNAL_TEST_RECIPIENTS": "jerryjiang128@gmail.com",
            "AIEOS_HANDOFF_HMAC_SECRET": "test-hmac-secret",
            "AIEOS_API_BASE_URL": "http://aieos.test",
            "AIEOS_OPERATOR_API_KEY": "test-operator-key",
        }, clear=False))
        self.gmail = _FakeGmail()
        self.receipts = []

    def _receipt(self, manifest, signature):
        self.receipts.append((manifest, signature))
        return {"stored": True}

    def test_dry_run_sends_nothing_and_creates_no_ledger(self):
        result = aieos_internal_test.deliver(
            _payload(), self.ledger, self.gmail, dry_run=True,
            receipt_sender=self._receipt,
        )
        self.assertEqual(result["result"], "dry_run")
        self.assertFalse(result["external_send"])
        self.assertEqual(self.gmail.calls, [])
        self.assertEqual(self.receipts, [])
        self.assertFalse(self.ledger.exists())

    def test_live_delivery_uses_only_test_recipient_and_records_receipt(self):
        result = aieos_internal_test.deliver(
            _payload(), self.ledger, self.gmail, dry_run=False,
            receipt_sender=self._receipt,
        )
        self.assertTrue(result["sent"])
        self.assertEqual(self.gmail.calls[0]["to"], "jerryjiang128@gmail.com")
        self.assertNotEqual(self.gmail.calls[0]["to"], "info@mimx.co.uk")
        self.assertEqual(self.receipts[0][0]["gmail_message_id"], "gmail-internal-1")
        row = aieos_internal_test.get(self.ledger, "test-id-1")
        self.assertEqual(row["status"], "COMPLETED")
        self.assertEqual(row["gmail_message_id"], "gmail-internal-1")

    def test_arbitrary_recipient_is_rejected(self):
        with self.assertRaisesRegex(InternalTestError, "INTERNAL_TEST_RECIPIENT_NOT_ALLOWED"):
            aieos_internal_test.deliver(
                _payload(test_recipient="other@example.test"), self.ledger,
                self.gmail, dry_run=True, receipt_sender=self._receipt,
            )
        self.assertEqual(self.gmail.calls, [])

    def test_customer_recipient_substitution_is_rejected(self):
        self.enterContext(patch.dict(os.environ, {
            "AIEOS_INTERNAL_TEST_RECIPIENTS": "jerryjiang128@gmail.com,info@mimx.co.uk",
        }, clear=False))
        with self.assertRaisesRegex(InternalTestError, "INTERNAL_TEST_RECIPIENT_IS_CUSTOMER"):
            aieos_internal_test.deliver(
                _payload(test_recipient="info@mimx.co.uk"), self.ledger,
                self.gmail, dry_run=True, receipt_sender=self._receipt,
            )

    def test_modified_sender_subject_or_body_is_rejected(self):
        for field in ("approved_by", "sender", "subject", "body"):
            with self.subTest(field=field):
                payload = _payload()
                payload[field] = "changed"
                with self.assertRaisesRegex(InternalTestError, "INTERNAL_TEST_FROZEN_CONTENT_MISMATCH"):
                    aieos_internal_test.deliver(
                        payload, self.ledger, self.gmail, dry_run=True,
                        receipt_sender=self._receipt,
                    )

    def test_invalid_signature_is_rejected(self):
        payload = _payload()
        payload["aieos_internal_test_signature"] = "0" * 64
        with self.assertRaisesRegex(InternalTestError, "INTERNAL_TEST_SIGNATURE_INVALID"):
            aieos_internal_test.deliver(payload, self.ledger, self.gmail, dry_run=True)

    def test_missing_approval_is_rejected(self):
        payload = _payload(approval_status="PREPARED")
        with self.assertRaisesRegex(InternalTestError, "INTERNAL_TEST_APPROVAL_REQUIRED"):
            aieos_internal_test.deliver(payload, self.ledger, self.gmail, dry_run=True)

    def test_duplicate_live_send_is_blocked(self):
        payload = _payload()
        first = aieos_internal_test.deliver(
            payload, self.ledger, self.gmail, dry_run=False,
            receipt_sender=self._receipt,
        )
        self.assertTrue(first["sent"])
        with self.assertRaisesRegex(InternalTestError, "INTERNAL_TEST_ALREADY_RESERVED"):
            aieos_internal_test.deliver(
                payload, self.ledger, self.gmail, dry_run=False,
                receipt_sender=self._receipt,
            )
        self.assertEqual(len(self.gmail.calls), 1)

    def test_customer_mode_cannot_enter_internal_test_path(self):
        with self.assertRaisesRegex(InternalTestError, "INTERNAL_TEST_MODE_REQUIRED"):
            aieos_internal_test.deliver(
                _payload(mode="CUSTOMER"), self.ledger, self.gmail, dry_run=True
            )


class InternalTestRouteTests(unittest.TestCase):
    def test_route_dry_run_does_not_touch_customer_prospects(self):
        import server

        with tempfile.TemporaryDirectory() as temp:
            prospects = Path(temp) / "prospects.json"
            prospects.write_text('[{"id":"laze","contact_email":"info@mimx.co.uk"}]', encoding="utf-8")
            before = prospects.read_bytes()
            headers = {
                "X-OutreachIQ-Bridge-Key": "test-bridge-key",
                "Content-Type": "application/json",
            }
            with patch.dict(os.environ, {
                "OUTREACHIQ_WEB_BRIDGE_KEY": "test-bridge-key",
                "OUTREACHIQ_WEB_BRIDGE_ALLOWED_NETWORKS": "127.0.0.1/32",
            }, clear=False), patch.object(server, "PROSPECTS_JSON", str(prospects)), patch.object(
                server.aieos_internal_test, "deliver", return_value={"result": "dry_run", "sent": False}
            ):
                server.app.config["TESTING"] = True
                response = server.app.test_client().post(
                    "/api/aieos/internal-test-send", json=_payload() | {"dry_run": True}, headers=headers
                )
            self.assertEqual(response.status_code, 200)
            self.assertEqual(prospects.read_bytes(), before)

class MimeUnicodeRegressionTests(unittest.TestCase):
    BODY = """Dear Emily,

I came across Laze & Amaze’s diode laser range and noticed that you also provide UK-based training, servicing and ongoing technical support to clinics.

We are a manufacturer of professional diode laser hair-removal systems in Shenzhen, and I thought there may be an opportunity to explore OEM/private-label supply or additional diode laser platforms for your range.

If this is relevant to your sourcing plans, I’d be happy to send a short product overview and specifications for you to review.

Best regards,

Jerry
Shenzhen IRIS Technology Co., Ltd.
iris@ibeautytech.com
https://www.ibeautytech.com
"""

    def test_canonical_body_serializes_as_utf8_crlf_without_unicode_mutation(self):
        from mailer.gmail_client import build_message
        message = build_message(to="jerryjiang128@gmail.com", subject="Diode laser OEM & supply cooperation", body_text=self.BODY, sender="iris@ibeautytech.com")
        raw = message.as_bytes(policy=policy.SMTP)
        self.assertNotIn(b"\n", raw.replace(b"\r\n", b""))
        parsed = BytesParser(policy=policy.default).parsebytes(raw)
        self.assertEqual(parsed.get_content_type(), "text/plain")
        self.assertEqual(parsed.get_content_charset(), "utf-8")
        self.assertEqual(parsed.get_content().replace("\r\n", "\n"), self.BODY)
        self.assertIn("Laze & Amaze’s diode laser range", parsed.get_content())
        self.assertIn("I’d be happy", parsed.get_content())