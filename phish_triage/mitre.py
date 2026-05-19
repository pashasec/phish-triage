"""Map observed phishing characteristics to MITRE ATT&CK techniques."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Technique:
    tid: str
    name: str
    reason: str


def map_techniques(
    has_url: bool,
    has_attachment: bool,
    has_dangerous_attachment: bool,
    has_macro_doc: bool,
    has_archive: bool,
    has_html_attachment: bool,
    has_lookalike: bool,
    auth_failed: bool,
) -> list[Technique]:
    techs: list[Technique] = []

    if has_attachment:
        techs.append(Technique(
            "T1566.001",
            "Phishing: Spearphishing Attachment",
            "Email carries one or more attachments",
        ))
    if has_url:
        techs.append(Technique(
            "T1566.002",
            "Phishing: Spearphishing Link",
            "Email contains clickable URLs",
        ))
    if has_macro_doc:
        techs.append(Technique(
            "T1204.002",
            "User Execution: Malicious File",
            "Attachment is a macro-enabled Office document",
        ))
    if has_html_attachment:
        techs.append(Technique(
            "T1566.001",
            "Phishing: Spearphishing Attachment (HTML smuggling)",
            "HTML attachment commonly used to deliver credential-harvest forms",
        ))
    if has_archive:
        techs.append(Technique(
            "T1027",
            "Obfuscated Files or Information",
            "Archive attachment can conceal payload from mail-gateway scanners",
        ))
    if has_dangerous_attachment:
        techs.append(Technique(
            "T1204.002",
            "User Execution: Malicious File",
            "Executable file type attached",
        ))
    if has_lookalike:
        techs.append(Technique(
            "T1583.001",
            "Acquire Infrastructure: Domains",
            "Sender domain appears to impersonate a known brand",
        ))
    if auth_failed:
        techs.append(Technique(
            "T1534",
            "Internal Spearphishing / Spoofing",
            "Email failed SPF/DKIM/DMARC -- sender identity is unverified",
        ))

    # Dedupe by tid+name
    seen = set()
    unique = []
    for t in techs:
        key = (t.tid, t.name)
        if key not in seen:
            seen.add(key)
            unique.append(t)
    return unique
