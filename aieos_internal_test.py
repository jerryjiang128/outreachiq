"""Fail-closed AIEOS INTERNAL_TEST delivery bridge.

This module is intentionally separate from OutreachIQ's CUSTOMER initial-send
state. It validates one signed AIEOS test handoff, reserves a dedicated
test-delivery ledger row, and calls the existing Gmail transport only for a
confirmed live request. Dry-run never reserves or calls Gmail.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import urllib.error
import urllib.request
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Callable

MODE = "INTERNAL_TEST"
RECIPIENT_ENV = "AIEOS_INTERNAL_TEST_RECIPIENTS"
HMAC_ENV = "AIEOS_HANDOFF_HMAC_SECRET"
AIEOS_API_ENV = "AIEOS_API_BASE_URL"
AIEOS_OPERATOR_ENV = "AIEOS_OPERATOR_API_KEY"

_PAYLOAD_FIELDS = {
    "mode", "test_send_only", "source_lead_id", "message_version",
    "test_recipient", "customer_recipient", "sender", "subject", "body",
    "test_id", "approval_status", "approved_by", "aieos_internal_test_manifest",
    "aieos_internal_test_signature", "dry_run",
}
_MANIFEST_FIELDS = {
    "source_system", "mode", "test_send_only", "approval_status",
    "approved_by_hash", "source_lead_id", "message_version", "test_id", "sender_hash",
    "test_recipient_hash", "customer_recipient_hash", "frozen_subject_hash",
    "frozen_body_hash",
}


class InternalTestError(RuntimeError):
    """A stable, browser-safe INTERNAL_TEST failure code."""


def _error(code: str) -> InternalTestError:
    return InternalTestError(code)


def canonical_frozen_text(value: str) -> str:
    if not isinstance(value, str):
        raise _error("INTERNAL_TEST_PAYLOAD_INVALID")
    return value.replace("\r\n", "\n").replace("\r", "\n")


def frozen_value_hash(value: str) -> str:
    return hashlib.sha256(canonical_frozen_text(value).encode("utf-8")).hexdigest()


def _required_text(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise _error("INTERNAL_TEST_PAYLOAD_INVALID")
    return value.strip()


def _allowed_recipients() -> set[str]:
    return {
        value.strip().casefold()
        for value in os.getenv(RECIPIENT_ENV, "").split(",")
        if value.strip()
    }


def _manifest_signature(manifest: dict[str, Any]) -> str:
    secret = os.getenv(HMAC_ENV)
    if not secret:
        raise _error("INTERNAL_TEST_SIGNATURE_NOT_CONFIGURED")
    encoded = json.dumps(
        manifest, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hmac.new(secret.encode("utf-8"), encoded, hashlib.sha256).hexdigest()


def _verify_manifest_signature(manifest: dict[str, Any], signature: Any) -> None:
    if not isinstance(signature, str) or not signature:
        raise _error("INTERNAL_TEST_SIGNATURE_REQUIRED")
    expected = _manifest_signature(manifest)
    if not hmac.compare_digest(signature, expected):
        raise _error("INTERNAL_TEST_SIGNATURE_INVALID")


def validate_payload(payload: Any) -> dict[str, Any]:
    """Validate one signed test payload and return an immutable snapshot."""

    if not isinstance(payload, dict):
        raise _error("INTERNAL_TEST_PAYLOAD_INVALID")
    if set(payload) - _PAYLOAD_FIELDS:
        raise _error("INTERNAL_TEST_PAYLOAD_INVALID")

    mode = _required_text(payload, "mode")
    if mode != MODE or payload.get("test_send_only") is not True:
        raise _error("INTERNAL_TEST_MODE_REQUIRED")

    approval_status = _required_text(payload, "approval_status")
    if approval_status != "APPROVED":
        raise _error("INTERNAL_TEST_APPROVAL_REQUIRED")
    approved_by = _required_text(payload, "approved_by")

    source_lead_id = _required_text(payload, "source_lead_id")
    message_version = _required_text(payload, "message_version")
    test_recipient = _required_text(payload, "test_recipient")
    customer_recipient = _required_text(payload, "customer_recipient")
    sender = _required_text(payload, "sender")
    subject = _required_text(payload, "subject")
    body = _required_text(payload, "body")
    test_id = _required_text(payload, "test_id")

    normalized_test = test_recipient.casefold()
    if normalized_test not in _allowed_recipients():
        raise _error("INTERNAL_TEST_RECIPIENT_NOT_ALLOWED")
    if normalized_test == customer_recipient.strip().casefold():
        raise _error("INTERNAL_TEST_RECIPIENT_IS_CUSTOMER")

    manifest = payload.get("aieos_internal_test_manifest")
    signature = payload.get("aieos_internal_test_signature")
    if not isinstance(manifest, dict) or set(manifest) != _MANIFEST_FIELDS:
        raise _error("INTERNAL_TEST_MANIFEST_INVALID")
    if (
        manifest.get("source_system") != "AIEOS"
        or manifest.get("mode") != MODE
        or manifest.get("test_send_only") is not True
        or manifest.get("approval_status") != "APPROVED"
        or manifest.get("source_lead_id") != source_lead_id
        or manifest.get("message_version") != message_version
        or manifest.get("test_id") != test_id
    ):
        raise _error("INTERNAL_TEST_MANIFEST_MISMATCH")
    _verify_manifest_signature(manifest, signature)

    expected_hashes = {
        "approved_by_hash": frozen_value_hash(approved_by),
        "sender_hash": frozen_value_hash(sender),
        "test_recipient_hash": frozen_value_hash(test_recipient),
        "customer_recipient_hash": frozen_value_hash(customer_recipient),
        "frozen_subject_hash": frozen_value_hash(subject),
        "frozen_body_hash": frozen_value_hash(body),
    }
    for field, value in expected_hashes.items():
        if not isinstance(manifest.get(field), str) or not hmac.compare_digest(manifest[field], value):
            raise _error("INTERNAL_TEST_FROZEN_CONTENT_MISMATCH")

    return {
        "mode": MODE,
        "test_send_only": True,
        "source_lead_id": source_lead_id,
        "message_version": message_version,
        "test_recipient": test_recipient,
        "customer_recipient": customer_recipient,
        "sender": sender,
        "subject": subject,
        "body": body,
        "test_id": test_id,
        "approval_status": "APPROVED",
        "subject_hash": expected_hashes["frozen_subject_hash"],
        "body_hash": expected_hashes["frozen_body_hash"],
        "manifest": manifest,
    }


@contextmanager
def _ledger(path: str | Path):
    ledger_path = Path(path)
    ledger_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(ledger_path, timeout=10)
    connection.row_factory = sqlite3.Row
    try:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS internal_test_delivery (
                test_id TEXT PRIMARY KEY,
                source_lead_id TEXT NOT NULL,
                message_version TEXT NOT NULL,
                status TEXT NOT NULL,
                snapshot_json TEXT NOT NULL,
                gmail_message_id TEXT,
                gmail_thread_id TEXT,
                receipt_json TEXT,
                error_code TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )"""
        )
        with connection:
            yield connection
    finally:
        connection.close()


def reserve(path: str | Path, snapshot: dict[str, Any], timestamp: str) -> bool:
    try:
        with _ledger(path) as connection:
            connection.execute(
                "INSERT INTO internal_test_delivery VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    snapshot["test_id"], snapshot["source_lead_id"],
                    snapshot["message_version"], "RESERVED",
                    json.dumps(snapshot, ensure_ascii=False, sort_keys=True),
                    None, None, None, None, timestamp, timestamp,
                ),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def update(
    path: str | Path, test_id: str, status: str, *, timestamp: str,
    gmail_message_id: str | None = None, gmail_thread_id: str | None = None,
    receipt: dict[str, Any] | None = None, error_code: str | None = None,
) -> None:
    with _ledger(path) as connection:
        connection.execute(
            """UPDATE internal_test_delivery
               SET status=?, gmail_message_id=?, gmail_thread_id=?, receipt_json=?,
                   error_code=?, updated_at=?
               WHERE test_id=?""",
            (
                status, gmail_message_id, gmail_thread_id,
                json.dumps(receipt, ensure_ascii=False, sort_keys=True) if receipt else None,
                error_code, timestamp, test_id,
            ),
        )


def get(path: str | Path, test_id: str) -> dict[str, Any] | None:
    with _ledger(path) as connection:
        row = connection.execute(
            "SELECT * FROM internal_test_delivery WHERE test_id=?", (test_id,)
        ).fetchone()
    return dict(row) if row else None


def receipt_configured() -> bool:
    return bool(os.getenv(AIEOS_API_ENV, "").strip() and os.getenv(AIEOS_OPERATOR_ENV, "").strip())


def post_receipt(manifest: dict[str, Any], signature: str) -> dict[str, Any]:
    """Post a signed receipt to AIEOS without exposing the operator key."""

    base = os.getenv(AIEOS_API_ENV, "").rstrip("/")
    key = os.getenv(AIEOS_OPERATOR_ENV, "")
    if not base or not key:
        raise _error("INTERNAL_TEST_RECEIPT_NOT_CONFIGURED")
    data = json.dumps({"manifest": manifest, "signature": signature}).encode("utf-8")
    request = urllib.request.Request(
        base + "/internal-test-deliveries/receipt",
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "X-AIEOS-Operator-Key": key},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read().decode("utf-8")
    except (urllib.error.HTTPError, urllib.error.URLError, OSError) as error:
        raise _error("INTERNAL_TEST_RECEIPT_FAILED") from error
    try:
        result = json.loads(raw) if raw else {}
    except json.JSONDecodeError as error:
        raise _error("INTERNAL_TEST_RECEIPT_INVALID") from error
    if not isinstance(result, dict):
        raise _error("INTERNAL_TEST_RECEIPT_INVALID")
    return result


def deliver(
    payload: Any,
    ledger_path: str | Path,
    gmail_client: Any,
    *,
    dry_run: bool = False,
    receipt_sender: Callable[[dict[str, Any], str], dict[str, Any]] | None = None,
    timestamp: str | None = None,
) -> dict[str, Any]:
    """Validate and optionally send one isolated internal test."""

    if not isinstance(dry_run, bool):
        raise _error("INTERNAL_TEST_DRY_RUN_INVALID")
    snapshot = validate_payload(payload)
    if dry_run:
        return {
            "result": "dry_run", "sent": False, "external_send": False,
            "mode": MODE, "source_lead_id": snapshot["source_lead_id"],
            "test_id": snapshot["test_id"], "test_recipient": snapshot["test_recipient"],
            "customer_recipient": snapshot["customer_recipient"],
            "subject_hash": snapshot["subject_hash"], "body_hash": snapshot["body_hash"],
        }

    if receipt_sender is None and not receipt_configured():
        raise _error("INTERNAL_TEST_RECEIPT_NOT_CONFIGURED")
    configured = getattr(gmail_client, "is_configured", None)
    if callable(configured) and not configured():
        raise _error("GMAIL_NOT_CONFIGURED")

    now = timestamp or datetime.now(UTC).isoformat()
    if not reserve(ledger_path, snapshot, now):
        raise _error("INTERNAL_TEST_ALREADY_RESERVED")

    try:
        result = gmail_client.send_email(
            to=snapshot["test_recipient"],
            subject=snapshot["subject"],
            body_text=snapshot["body"],
        )
        message_id = result.get("message_id") if isinstance(result, dict) else None
        if not isinstance(message_id, str) or not message_id:
            raise _error("GMAIL_MESSAGE_ID_MISSING")
        thread_id = result.get("thread_id", "") if isinstance(result, dict) else ""
        receipt_manifest = {
            **snapshot["manifest"],
            "gmail_message_id": message_id,
            "gmail_thread_id": thread_id,
            "delivered_at": now,
        }
        receipt_signature = _manifest_signature(receipt_manifest)
        sender = receipt_sender or post_receipt
        receipt = sender(receipt_manifest, receipt_signature)
        if not isinstance(receipt, dict):
            raise _error("INTERNAL_TEST_RECEIPT_INVALID")
        update(
            ledger_path, snapshot["test_id"], "COMPLETED", timestamp=now,
            gmail_message_id=message_id, gmail_thread_id=thread_id, receipt=receipt,
        )
        return {
            "result": "sent", "sent": True, "external_send": True,
            "mode": MODE, "source_lead_id": snapshot["source_lead_id"],
            "test_id": snapshot["test_id"], "test_recipient": snapshot["test_recipient"],
            "customer_recipient": snapshot["customer_recipient"],
            "gmail_message_id": message_id, "gmail_thread_id": thread_id,
            "receipt": receipt,
        }
    except InternalTestError as error:
        update(ledger_path, snapshot["test_id"], "RECONCILIATION_REQUIRED", timestamp=now, error_code=str(error))
        raise
    except Exception as error:
        update(
            ledger_path, snapshot["test_id"], "RECONCILIATION_REQUIRED",
            timestamp=now, error_code=getattr(error, "code", type(error).__name__),
        )
        raise _error("INTERNAL_TEST_DELIVERY_RECONCILIATION_REQUIRED") from error
