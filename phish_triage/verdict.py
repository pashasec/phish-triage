"""Combine signals into a single verdict + confidence score.

Scoring is additive with weights tuned so that any one strong signal pushes
into 'suspicious', and 2+ moderate signals push into 'confirmed'. The intent
is conservative -- false positives are worse for SOC throughput than missing
edge cases that an analyst would still review.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal


Severity = Literal["clean", "suspicious", "likely-phishing", "confirmed-phishing"]


@dataclass
class Verdict:
    severity: Severity
    score: int
    reasons: list[str]


def score_email(
    *,
    auth_all_fail: bool,
    auth_any_fail: bool,
    lookalike_domain: bool,
    newly_registered: bool,  # <30d
    young_domain: bool,      # 30-180d
    reply_to_mismatch: bool,
    shortened_urls: int,
    dangerous_attachment: bool,
    macro_attachment: bool,
    html_attachment: bool,
    external_malicious_hits: int,
    external_suspicious_hits: int,
    timestamp_skew_large: bool,
) -> Verdict:
    score = 0
    reasons: list[str] = []

    if auth_all_fail:
        score += 40
        reasons.append("All three auth checks (SPF/DKIM/DMARC) FAIL (+40)")
    elif auth_any_fail:
        score += 20
        reasons.append("At least one auth check failed (+20)")

    if lookalike_domain:
        score += 35
        reasons.append("Sender domain looks like a known brand (+35)")

    if newly_registered:
        score += 30
        reasons.append("Sender domain registered <30 days ago (+30)")
    elif young_domain:
        score += 15
        reasons.append("Sender domain registered <180 days ago (+15)")

    if reply_to_mismatch:
        score += 15
        reasons.append("Reply-To domain differs from From domain (+15)")

    if shortened_urls > 0:
        added = min(20, 10 + shortened_urls * 5)
        score += added
        reasons.append(f"{shortened_urls} shortened URL(s) (+{added})")

    if dangerous_attachment:
        score += 40
        reasons.append("Executable file type attached (+40)")
    if macro_attachment:
        score += 25
        reasons.append("Macro-enabled document attached (+25)")
    if html_attachment:
        score += 25
        reasons.append("HTML attachment -- credential-phish vector (+25)")

    if external_malicious_hits > 0:
        added = min(50, 25 * external_malicious_hits)
        score += added
        reasons.append(f"{external_malicious_hits} external source(s) flagged malicious (+{added})")
    if external_suspicious_hits > 0:
        added = min(20, 10 * external_suspicious_hits)
        score += added
        reasons.append(f"{external_suspicious_hits} external source(s) flagged suspicious (+{added})")

    if timestamp_skew_large:
        score += 10
        reasons.append("Large timestamp skew across hops (+10)")

    if score >= 80:
        severity: Severity = "confirmed-phishing"
    elif score >= 50:
        severity = "likely-phishing"
    elif score >= 20:
        severity = "suspicious"
    else:
        severity = "clean"

    return Verdict(severity=severity, score=score, reasons=reasons)
