"""Mail transports for OutreachIQ; INTERNAL_TEST is sender-bound and fail-closed."""

import base64
import os
import smtplib
import ssl
from email import policy
from email.message import EmailMessage
from email.utils import make_msgid

from config import GMAIL_CLIENT_SECRET_FILE, GMAIL_TOKEN_FILE, GMAIL_SCOPES, GMAIL_SENDER


class GmailNotConfigured(RuntimeError):
    """Raised when Gmail credentials / token are missing."""


class MailTransportNotConfigured(RuntimeError):
    """Raised when an INTERNAL_TEST sender has no safe transport."""


def _transport_name() -> str:
    return os.getenv("OUTREACH_MAIL_TRANSPORT", "gmail_api").strip().casefold()


def _header_value(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or "\r" in value or "\n" in value:
        raise MailTransportNotConfigured(f"Invalid {field} header")
    return value.strip()


def build_message(*, to: str, subject: str, body_text: str, sender: str) -> EmailMessage:
    """Create deterministic UTF-8 MIME with RFC 5322 CRLF serialization."""
    message = EmailMessage(policy=policy.SMTP)
    message["To"] = _header_value(to, "To")
    message["From"] = _header_value(sender, "From")
    message["Subject"] = _header_value(subject, "Subject")
    message["Message-ID"] = make_msgid(domain=sender.rsplit("@", 1)[-1])
    message.set_content(body_text, subtype="plain", charset="utf-8", cte="quoted-printable")
    return message


def _zoho_settings() -> dict[str, object]:
    host=os.getenv("ZOHO_SMTP_HOST", "").strip(); username=os.getenv("ZOHO_SMTP_USERNAME", "").strip()
    password=os.getenv("ZOHO_SMTP_APP_PASSWORD", ""); sender=os.getenv("ZOHO_SMTP_FROM", "").strip()
    tls_mode=os.getenv("ZOHO_SMTP_TLS_MODE", "").strip().upper()
    try: port=int(os.getenv("ZOHO_SMTP_PORT", ""))
    except ValueError: port=0
    if not all((host, username, password, sender)) or port <= 0 or tls_mode not in {"SSL", "STARTTLS"}:
        raise MailTransportNotConfigured("ZOHO_SMTP_NOT_CONFIGURED")
    if username.casefold() != sender.casefold():
        raise MailTransportNotConfigured("ZOHO_SMTP_ENVELOPE_FROM_MISMATCH")
    return {"host":host,"port":port,"username":username,"password":password,"sender":sender,"tls_mode":tls_mode}


def _zoho_client(settings: dict[str, object], timeout: int):
    context=ssl.create_default_context()
    if settings["tls_mode"] == "SSL":
        return smtplib.SMTP_SSL(str(settings["host"]), int(settings["port"]), timeout=timeout, context=context)
    client=smtplib.SMTP(str(settings["host"]), int(settings["port"]), timeout=timeout)
    client.starttls(context=context)
    return client


def is_sender_authorized(sender: str) -> bool:
    """Fail closed unless transport configuration is exact for the frozen sender."""
    try:
        if _transport_name() == "zoho_smtp":
            return str(_zoho_settings()["sender"]).casefold() == sender.strip().casefold()
        if _transport_name() == "gmail_api":
            return bool(GMAIL_SENDER) and GMAIL_SENDER.casefold() == sender.strip().casefold() and get_profile().get("email_address", "").casefold() == sender.strip().casefold()
    except Exception:
        return False
    return False


def preflight_zoho_smtp(sender: str) -> dict[str, object]:
    """Authenticate only; never issue MAIL, RCPT, DATA, sendmail, or send_message."""
    if _transport_name() != "zoho_smtp":
        raise MailTransportNotConfigured("ZOHO_SMTP_TRANSPORT_REQUIRED")
    settings=_zoho_settings()
    if str(settings["sender"]).casefold() != sender.strip().casefold():
        raise MailTransportNotConfigured("ZOHO_SMTP_SENDER_MISMATCH")
    client=_zoho_client(settings, 10)
    try:
        client.login(str(settings["username"]), str(settings["password"]))
        return {"transport":"zoho_smtp","authenticated_sender":settings["sender"],"envelope_from":settings["username"],"header_from":settings["sender"]}
    finally:
        client.quit()


def _load_credentials():
    try:
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request
    except ImportError as e:
        raise GmailNotConfigured("Google API libraries not installed") from e
    if not os.path.exists(GMAIL_TOKEN_FILE):
        raise GmailNotConfigured("Gmail not authorized")
    creds=Credentials.from_authorized_user_file(GMAIL_TOKEN_FILE, GMAIL_SCOPES)
    if creds and creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(GMAIL_TOKEN_FILE, "w", encoding="utf-8") as f: f.write(creds.to_json())
    if not creds or not creds.valid: raise GmailNotConfigured("Gmail token invalid")
    return creds


def _service():
    from googleapiclient.discovery import build
    return build("gmail", "v1", credentials=_load_credentials(), cache_discovery=False)


def is_configured() -> bool:
    try: _load_credentials(); return True
    except Exception: return False


def get_profile() -> dict:
    profile=_service().users().getProfile(userId="me").execute()
    return {"email_address":profile.get("emailAddress", ""),"messages_total":profile.get("messagesTotal"),"threads_total":profile.get("threadsTotal")}


def status() -> dict:
    have_secret=os.path.exists(GMAIL_CLIENT_SECRET_FILE); have_token=os.path.exists(GMAIL_TOKEN_FILE)
    try: import google.oauth2.credentials; libs=True
    except ImportError: libs=False
    state="ok" if libs and have_secret and have_token and is_configured() else ("libs_missing" if not libs else "no_client_secret" if not have_secret else "not_authorized" if not have_token else "token_invalid")
    return {"state":state,"ok":state=="ok","sender":GMAIL_SENDER,"scopes":GMAIL_SCOPES}


def _send_via_zoho(message: EmailMessage, settings: dict[str, object]) -> dict:
    client=_zoho_client(settings, 20)
    try:
        client.login(str(settings["username"]), str(settings["password"]))
        client.send_message(message, from_addr=str(settings["username"]), to_addrs=[str(message["To"])])
    finally:
        client.quit()
    return {"message_id":str(message["Message-ID"]),"thread_id":"","transport":"zoho_smtp"}


def send_email(to: str, subject: str, body_text: str, thread_id: str | None = None, sender: str | None = None) -> dict:
    """Send only through the explicitly configured, sender-authorized transport."""
    transport=_transport_name()
    if transport == "zoho_smtp":
        settings=_zoho_settings(); effective_sender=sender or str(settings["sender"])
        if str(settings["sender"]).casefold() != effective_sender.casefold(): raise MailTransportNotConfigured("ZOHO_SMTP_SENDER_MISMATCH")
        return _send_via_zoho(build_message(to=to,subject=subject,body_text=body_text,sender=effective_sender), settings)
    if transport != "gmail_api": raise MailTransportNotConfigured("MAIL_TRANSPORT_UNSUPPORTED")
    effective_sender=sender or GMAIL_SENDER
    if not is_sender_authorized(effective_sender): raise MailTransportNotConfigured("GMAIL_SENDER_NOT_AUTHORIZED")
    message=build_message(to=to,subject=subject,body_text=body_text,sender=effective_sender)
    payload={"raw":base64.urlsafe_b64encode(message.as_bytes(policy=policy.SMTP)).decode("ascii")}
    if thread_id: payload["threadId"]=thread_id
    sent=_service().users().messages().send(userId="me",body=payload).execute()
    return {"message_id":sent.get("id", ""),"thread_id":sent.get("threadId", ""),"transport":"gmail_api"}
def list_replies(thread_ids: list[str]) -> list[dict]:
    """For each thread, return inbound (received) messages newer than the
    thread's first message. Read-only.

    Returns: [{thread_id, message_id, from, snippet, received_at}]
    """
    if not thread_ids:
        return []
    service = _service()

    # Identify our own address so we can distinguish inbound from our sends.
    me = (GMAIL_SENDER or "").lower()
    if not me:
        try:
            profile = service.users().getProfile(userId="me").execute()
            me = (profile.get("emailAddress") or "").lower()
        except Exception:
            me = ""

    replies = []
    for tid in thread_ids:
        if not tid:
            continue
        try:
            thread = service.users().threads().get(
                userId="me", id=tid, format="metadata",
                metadataHeaders=["From", "Date"],
            ).execute()
        except Exception:
            continue
        messages = thread.get("messages", [])
        for msg in messages:
            headers = {h["name"].lower(): h["value"]
                       for h in msg.get("payload", {}).get("headers", [])}
            sender = (headers.get("from", "") or "").lower()
            label_ids = msg.get("labelIds", [])
            is_inbound = "SENT" not in label_ids and (not me or me not in sender)
            if not is_inbound:
                continue
            replies.append({
                "thread_id": tid,
                "message_id": msg.get("id", ""),
                "from": headers.get("from", ""),
                "snippet": msg.get("snippet", ""),
                "received_at": headers.get("date", ""),
            })
    return replies
