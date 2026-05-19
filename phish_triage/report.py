"""Render the triage report as markdown + emit an IOC CSV for SIEM ingestion."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from io import StringIO
from typing import Iterable

from .attachments import HashedAttachment
from .domain import DomainAnalysis
from .enrich import EnrichmentResult
from .headers import HeaderAnalysis
from .mitre import Technique
from .parser import ParsedEmail
from .urls import ExtractedURL
from .verdict import Verdict


SEVERITY_BADGE = {
    "clean": "CLEAN",
    "suspicious": "SUSPICIOUS",
    "likely-phishing": "LIKELY PHISHING",
    "confirmed-phishing": "CONFIRMED PHISHING",
}


@dataclass
class TriageBundle:
    email: ParsedEmail
    headers: HeaderAnalysis
    sender_domain: DomainAnalysis
    urls: list[ExtractedURL]
    attachments: list[HashedAttachment]
    enrichments: dict[str, list[EnrichmentResult]]  # keyed by indicator (url/host/ip/hash)
    techniques: list[Technique]
    verdict: Verdict


def render_markdown(b: TriageBundle) -> str:
    lines: list[str] = []
    e = b.email

    lines.append(f"# Phishing Triage Report -- {e.subject or '(no subject)'}")
    lines.append("")
    lines.append(f"**Verdict:** {SEVERITY_BADGE[b.verdict.severity]}  (score {b.verdict.score})")
    lines.append("")

    lines.append("## Sender")
    lines.append("")
    lines.append(f"- **From:** `{e.from_addr}` ({e.from_name or 'no display name'})")
    if e.reply_to and e.reply_to != e.from_addr:
        lines.append(f"- **Reply-To:** `{e.reply_to}`  [!] mismatch with From")
    elif e.reply_to:
        lines.append(f"- **Reply-To:** `{e.reply_to}`")
    if e.return_path:
        lines.append(f"- **Return-Path:** `{e.return_path}`")
    lines.append(f"- **Date:** {e.date}")
    lines.append(f"- **Message-ID:** `{e.message_id}`")
    lines.append("")

    sd = b.sender_domain
    lines.append("## Sender Domain")
    lines.append("")
    lines.append(f"- **Domain:** `{sd.registered_domain}`")
    if sd.creation_date:
        lines.append(f"- **Registered:** {sd.creation_date} ({sd.age_days}d ago)")
    if sd.registrar:
        lines.append(f"- **Registrar:** {sd.registrar}")
    if sd.lookalike_of:
        lines.append(f"- [!] **Lookalike of:** `{sd.lookalike_of}` (edit distance {sd.lookalike_distance})")
    for f in sd.flags:
        lines.append(f"- [!] {f}")
    lines.append("")

    h = b.headers
    lines.append("## Authentication")
    lines.append("")
    lines.append(f"- **SPF:** {h.auth.spf.upper()}")
    lines.append(f"- **DKIM:** {h.auth.dkim.upper()}")
    lines.append(f"- **DMARC:** {h.auth.dmarc.upper()}")
    lines.append("")

    lines.append("## Hop Analysis")
    lines.append("")
    if not h.hops:
        lines.append("_No Received headers parsed._")
    else:
        for hop in h.hops:
            ts = hop.timestamp.isoformat() if hop.timestamp else "unknown"
            parts = []
            if hop.from_host:
                parts.append(f"from `{hop.from_host}`")
            if hop.from_ip:
                parts.append(f"[`{hop.from_ip}`]")
            if hop.by_host:
                parts.append(f"-> `{hop.by_host}`")
            lines.append(f"{hop.index}. {' '.join(parts)}  ({ts})")
    if h.anomalies:
        lines.append("")
        lines.append("**Anomalies:**")
        for a in h.anomalies:
            lines.append(f"- [!] {a}")
    lines.append("")

    lines.append("## URLs")
    lines.append("")
    if not b.urls:
        lines.append("_No URLs found in the body._")
    else:
        for u in b.urls:
            marker = "[!] " if u.is_shortener else ""
            line = f"- {marker}`{u.defanged}`"
            if u.expanded:
                line += f"  -> expands to `{u.expanded}`"
            line += f"  _(found in {u.found_in})_"
            lines.append(line)
            host_enrich = b.enrichments.get(u.host, []) + b.enrichments.get(u.raw, [])
            for er in host_enrich:
                lines.append(f"    - **{er.source}:** {er.verdict.upper()} -- {er.detail}")
    lines.append("")

    lines.append("## Attachments")
    lines.append("")
    if not b.attachments:
        lines.append("_No attachments._")
    else:
        for a in b.attachments:
            lines.append(f"- **{a.filename}** ({a.content_type}, {a.size} bytes)")
            lines.append(f"    - SHA256: `{a.sha256}`")
            lines.append(f"    - SHA1: `{a.sha1}`")
            lines.append(f"    - MD5: `{a.md5}`")
            for flag in a.risk_flags:
                lines.append(f"    - [!] {flag}")
            for er in b.enrichments.get(a.sha256, []):
                lines.append(f"    - **{er.source}:** {er.verdict.upper()} -- {er.detail}")
    lines.append("")

    lines.append("## MITRE ATT&CK")
    lines.append("")
    if not b.techniques:
        lines.append("_No techniques mapped._")
    else:
        for t in b.techniques:
            lines.append(f"- **{t.tid}** -- {t.name}  _({t.reason})_")
    lines.append("")

    lines.append("## Verdict Detail")
    lines.append("")
    lines.append(f"**Score:** {b.verdict.score}")
    lines.append("")
    lines.append("**Contributing signals:**")
    for r in b.verdict.reasons:
        lines.append(f"- {r}")
    lines.append("")

    return "\n".join(lines)


def render_iocs_csv(b: TriageBundle) -> str:
    """Render every concrete indicator into a CSV suitable for SIEM blocklist import.

    Columns: type, value, context, source_verdict
    """
    buf = StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(["type", "value", "context", "source_verdict"])

    if b.email.from_addr:
        w.writerow(["email", b.email.from_addr, "From header", b.verdict.severity])

    sd = b.sender_domain.registered_domain
    if sd:
        w.writerow(["domain", sd, "sender domain", b.verdict.severity])

    for hop in b.headers.hops:
        if hop.from_ip:
            w.writerow(["ip", hop.from_ip, f"Received hop {hop.index}", b.verdict.severity])

    for u in b.urls:
        ext_verdicts = ",".join(
            f"{er.source}:{er.verdict}" for er in b.enrichments.get(u.host, []) + b.enrichments.get(u.raw, [])
        )
        w.writerow(["url", u.raw, f"body ({u.found_in})", ext_verdicts or b.verdict.severity])
        if u.host:
            w.writerow(["domain", u.host, "URL host", ext_verdicts or b.verdict.severity])
        if u.expanded:
            w.writerow(["url", u.expanded, "expanded shortener", ext_verdicts or b.verdict.severity])

    for a in b.attachments:
        ext_verdicts = ",".join(f"{er.source}:{er.verdict}" for er in b.enrichments.get(a.sha256, []))
        w.writerow(["sha256", a.sha256, f"attachment {a.filename}", ext_verdicts or b.verdict.severity])
        w.writerow(["sha1", a.sha1, f"attachment {a.filename}", ext_verdicts or b.verdict.severity])
        w.writerow(["md5", a.md5, f"attachment {a.filename}", ext_verdicts or b.verdict.severity])

    return buf.getvalue()
