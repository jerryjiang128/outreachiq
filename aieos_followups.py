"""AIEOS approval extension for the existing follow-up import/send engine."""
import copy
import hashlib
import hmac
import json
import os
import re
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

IDENTITY = ("source_lead_id", "followup_id", "original_gmail_thread_id", "message_version",
            "followup_type", "recipient_hash", "subject_hash", "body_hash")


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def operator_error(operator_key):
    expected = os.getenv("AIEOS_OPERATOR_API_KEY")
    if not expected:
        return "FOLLOWUP_OPERATOR_AUTH_UNCONFIGURED"
    if not isinstance(operator_key, str) or not operator_key:
        return "FOLLOWUP_OPERATOR_AUTH_REQUIRED"
    if not hmac.compare_digest(operator_key.encode(), expected.encode()):
        return "FOLLOWUP_OPERATOR_AUTH_INVALID"
    return None


def approval_proof(signature):
    key = os.getenv("AIEOS_OPERATOR_API_KEY")
    if not key:
        return ""
    return hmac.new(key.encode(), ("FOLLOWUP_APPROVAL:" + signature).encode(),
                    hashlib.sha256).hexdigest()


def batch_operator_error(prospects, operator_key):
    if any(r.get("review_status") in ("PENDING_REVIEW", "Approved")
           for lead in prospects for r in lead.get("aieos_followups", [])):
        return operator_error(operator_key)
    return None


def validate(lead, record, require_approval=False):
    if not isinstance(record, dict):
        return "FOLLOWUP_METADATA_MISSING"
    manifest = record.get("manifest")
    if not isinstance(manifest, dict):
        return "FOLLOWUP_MANIFEST_MISSING"
    secret = os.getenv("AIEOS_HANDOFF_HMAC_SECRET")
    signature = record.get("signature")
    if not secret or not isinstance(signature, str):
        return "FOLLOWUP_SIGNATURE_MISSING"
    expected = hmac.new(secret.encode(), json.dumps(manifest, sort_keys=True,
        ensure_ascii=False, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return "FOLLOWUP_SIGNATURE_INVALID"
    for field in ("source_system", "mode", *IDENTITY):
        if not isinstance(manifest.get(field), str) or not manifest[field]:
            return "FOLLOWUP_IDENTITY_MISSING"
        if record.get(field) != manifest[field]:
            return "FOLLOWUP_IDENTITY_MISMATCH:" + field
    if manifest["source_system"] != "AIEOS" or manifest["mode"] != "FOLLOWUP":
        return "FOLLOWUP_MODE_INVALID"
    if manifest["followup_type"] not in ("STANDARD", "CORRECTION"):
        return "FOLLOWUP_TYPE_INVALID"
    if lead.get("status") != "sent":
        return "FOLLOWUP_REQUIRES_SENT_LEAD"
    if lead.get("gmail_thread_id") != manifest["original_gmail_thread_id"]:
        return "FOLLOWUP_THREAD_MISMATCH"
    source = (lead.get("aieos_handoff_manifest") or {}).get("source_lead_id")
    source = source or lead.get("aieos_followup_source_lead_id")
    if source and source != manifest["source_lead_id"]:
        return "FOLLOWUP_SOURCE_MISMATCH"
    if lead.get("contact_email") != record.get("recipient"):
        return "FOLLOWUP_RECIPIENT_MISMATCH"
    for field in ("recipient", "subject", "body"):
        value = record.get(field)
        if not isinstance(value, str) or not value.strip():
            return "FOLLOWUP_CONTENT_MISSING"
        if digest(value) != manifest[field + "_hash"]:
            return "FOLLOWUP_HASH_MISMATCH:" + field
    if re.search(r"\[Your Name\]|\[Company\]|you@example\.com|www\.example\.com|\{\{|\}\}|<[^>]+>|\[[^]]+\]",
                 record["body"] + record["subject"], re.I):
        return "FOLLOWUP_PLACEHOLDER"
    if require_approval and (record.get("used") is not False or record.get("status") != "Approved"
            or record.get("review_status") != "Approved"
            or record.get("approved_signature") != signature or not record.get("approved_at")):
        return "FOLLOWUP_HUMAN_APPROVAL_REQUIRED"
    if require_approval:
        proof = record.get("operator_approval_proof")
        expected_proof = approval_proof(signature)
        if not expected_proof or not isinstance(proof, str) or not hmac.compare_digest(
                proof.encode(), expected_proof.encode()):
            return "FOLLOWUP_OPERATOR_APPROVAL_REQUIRED"
    return None


@contextmanager
def ledger(path):
    c = sqlite3.connect(path, timeout=10)
    c.execute("""CREATE TABLE IF NOT EXISTS followup_delivery (
        source_lead_id TEXT NOT NULL, followup_id TEXT NOT NULL UNIQUE,
        message_version TEXT NOT NULL, body_hash TEXT NOT NULL,
        status TEXT NOT NULL, gmail_message_id TEXT, gmail_thread_id TEXT,
        UNIQUE(source_lead_id, message_version))""")
    try:
        with c:
            yield c
    finally:
        c.close()


def delivery_exists(path, record):
    if not os.path.exists(path):
        return False
    with ledger(path) as c:
        return c.execute("""SELECT 1 FROM followup_delivery
            WHERE followup_id=? OR (source_lead_id=? AND message_version=?)""",
            (record["followup_id"], record["source_lead_id"], record["message_version"])).fetchone() is not None


def reserve(path, record):
    try:
        with ledger(path) as c:
            c.execute("INSERT INTO followup_delivery VALUES (?,?,?,?, 'RESERVED',NULL,NULL)",
                tuple(record[k] for k in ("source_lead_id", "followup_id", "message_version", "body_hash")))
        return True
    except sqlite3.IntegrityError:
        return False


def mark_delivered(path, record, result):
    with ledger(path) as c:
        c.execute("""UPDATE followup_delivery SET status='Used', gmail_message_id=?,
            gmail_thread_id=? WHERE followup_id=?""",
            (result["message_id"], result["thread_id"], record["followup_id"]))


def import_record(prospects, lead, entry, path):
    record = copy.deepcopy(entry)
    record.pop("id", None)
    error = validate(lead, record)
    if error:
        raise ValueError(error)
    if delivery_exists(path, record):
        raise ValueError("FOLLOWUP_VERSION_ALREADY_RESERVED_OR_USED")
    for prospect in prospects:
        for old in prospect.get("aieos_followups", []):
            if (old["followup_id"] == record["followup_id"] or
                    (old["source_lead_id"], old["message_version"]) ==
                    (record["source_lead_id"], record["message_version"])):
                if (prospect["id"] == lead["id"] and old["manifest"] == record["manifest"]
                        and old["signature"] == record["signature"]):
                    # Idempotent import never resets approval or used state.
                    return False
                raise ValueError("FOLLOWUP_VERSION_EXISTS")
    record.update(status="drafted", review_status="PENDING_REVIEW", used=False,
                  approved_at=None, approved_signature=None, operator_approval_proof=None)
    lead.setdefault("aieos_followups", []).append(record)
    lead["aieos_followup_source_lead_id"] = record["source_lead_id"]
    return True


def approve(lead, followup_id, path, operator_key=None):
    error = operator_error(operator_key)
    if error:
        raise ValueError(error)
    matches = [r for r in lead.get("aieos_followups", []) if r["followup_id"] == followup_id]
    if len(matches) != 1:
        raise ValueError("FOLLOWUP_NOT_FOUND")
    record = matches[0]
    error = validate(lead, record)
    if error:
        raise ValueError(error)
    if record.get("review_status") != "PENDING_REVIEW" or delivery_exists(path, record):
        raise ValueError("FOLLOWUP_NOT_PENDING")
    record.update(status="Approved", review_status="Approved",
                  operator_approval_proof=approval_proof(record["signature"]),
                  approved_signature=record["signature"],
                  approved_at=datetime.now(timezone.utc).isoformat())
    return record



def receipt(record, result):
    manifest = {"source_system": "AIEOS", "mode": "FOLLOWUP_RECEIPT",
                **{key: record[key] for key in IDENTITY},
                "gmail_message_id": result["message_id"], "gmail_thread_id": result["thread_id"]}
    secret = os.environ["AIEOS_HANDOFF_HMAC_SECRET"]
    signature = hmac.new(secret.encode(), json.dumps(manifest, sort_keys=True,
        ensure_ascii=False, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
    return {"manifest": manifest, "signature": signature}
