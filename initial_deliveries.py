"""Durable immutable delivery snapshots for AIEOS Initial Sends."""
import json
import sqlite3
from contextlib import contextmanager


@contextmanager
def ledger(path):
    connection = sqlite3.connect(path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("""CREATE TABLE IF NOT EXISTS initial_delivery (
        source_lead_id TEXT NOT NULL UNIQUE, send_prep_id TEXT NOT NULL UNIQUE,
        message_version TEXT NOT NULL, status TEXT NOT NULL, snapshot_json TEXT NOT NULL,
        gmail_message_id TEXT, gmail_thread_id TEXT, error_code TEXT,
        PRIMARY KEY (source_lead_id, send_prep_id, message_version))""")
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def reserve(path, snapshot):
    try:
        with ledger(path) as connection:
            connection.execute("INSERT INTO initial_delivery VALUES (?,?,?,?,?,?,?,?)", (
                snapshot["source_lead_id"], snapshot["send_prep_id"], snapshot["message_version"],
                "RESERVED", json.dumps(snapshot, ensure_ascii=False, sort_keys=True), None, None, None,
            ))
        return True
    except sqlite3.IntegrityError:
        return False


def update(path, snapshot, status, result=None, error=None):
    result = result or {}
    with ledger(path) as connection:
        connection.execute("""UPDATE initial_delivery SET status=?, gmail_message_id=?, gmail_thread_id=?, error_code=?
            WHERE source_lead_id=? AND send_prep_id=? AND message_version=?""", (
            status, result.get("message_id") or None, result.get("thread_id") or None, error,
            snapshot["source_lead_id"], snapshot["send_prep_id"], snapshot["message_version"],
        ))


def get(path, snapshot):
    with ledger(path) as connection:
        row = connection.execute("SELECT * FROM initial_delivery WHERE source_lead_id=?", (snapshot["source_lead_id"],)).fetchone()
    return dict(row) if row else None
