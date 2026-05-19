"""Parse a .eml file into structured fields the rest of the pipeline consumes."""

from __future__ import annotations

import email
import email.policy
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import getaddresses, parseaddr
from pathlib import Path
from typing import Optional


@dataclass
class Attachment:
    filename: str
    content_type: str
    size: int
    payload: bytes


@dataclass
class ParsedEmail:
    raw: bytes
    subject: str
    from_addr: str
    from_name: str
    reply_to: str
    return_path: str
    to_addrs: list[str]
    cc_addrs: list[str]
    date: str
    message_id: str
    received_headers: list[str]
    auth_results: str
    body_text: str
    body_html: str
    attachments: list[Attachment] = field(default_factory=list)
    all_headers: list[tuple[str, str]] = field(default_factory=list)


def _addr(value: Optional[str]) -> str:
    if not value:
        return ""
    _, addr = parseaddr(value)
    return addr.lower()


def _name_from(value: Optional[str]) -> str:
    if not value:
        return ""
    name, _ = parseaddr(value)
    return name


def _addr_list(msg: EmailMessage, header: str) -> list[str]:
    values = msg.get_all(header, [])
    return [a.lower() for _, a in getaddresses(values) if a]


def _decode_payload(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except (LookupError, UnicodeDecodeError, AssertionError):
        raw = part.get_payload(decode=True) or b""
        return raw.decode("utf-8", errors="replace")


def parse_eml(path: Path | str) -> ParsedEmail:
    """Parse an .eml file from disk."""
    data = Path(path).read_bytes()
    return parse_bytes(data)


def parse_bytes(data: bytes) -> ParsedEmail:
    """Parse a raw RFC 822 message."""
    msg: EmailMessage = email.message_from_bytes(data, policy=email.policy.default)  # type: ignore[assignment]

    body_text = ""
    body_html = ""
    attachments: list[Attachment] = []

    if msg.is_multipart():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disp = (part.get_content_disposition() or "").lower()
            ctype = part.get_content_type()
            if disp == "attachment" or part.get_filename():
                payload = part.get_payload(decode=True) or b""
                attachments.append(
                    Attachment(
                        filename=part.get_filename() or "unnamed",
                        content_type=ctype,
                        size=len(payload),
                        payload=payload,
                    )
                )
            elif ctype == "text/plain" and not body_text:
                body_text = _decode_payload(part)
            elif ctype == "text/html" and not body_html:
                body_html = _decode_payload(part)
    else:
        ctype = msg.get_content_type()
        content = _decode_payload(msg)
        if ctype == "text/html":
            body_html = content
        else:
            body_text = content

    return ParsedEmail(
        raw=data,
        subject=msg.get("Subject", "") or "",
        from_addr=_addr(msg.get("From")),
        from_name=_name_from(msg.get("From")),
        reply_to=_addr(msg.get("Reply-To")),
        return_path=_addr(msg.get("Return-Path")),
        to_addrs=_addr_list(msg, "To"),
        cc_addrs=_addr_list(msg, "Cc"),
        date=msg.get("Date", "") or "",
        message_id=msg.get("Message-ID", "") or "",
        received_headers=msg.get_all("Received", []) or [],
        auth_results=" ".join(msg.get_all("Authentication-Results", []) or []),
        body_text=body_text,
        body_html=body_html,
        attachments=attachments,
        all_headers=list(msg.items()),
    )
