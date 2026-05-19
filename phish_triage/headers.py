"""SPF/DKIM/DMARC verdicts + Received hop analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Optional


IPV4_RE = re.compile(r"\b((?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3})\b")
HOSTNAME_RE = re.compile(r"from\s+([\w.\-]+)", re.IGNORECASE)
BY_RE = re.compile(r"by\s+([\w.\-]+)", re.IGNORECASE)


@dataclass
class AuthVerdict:
    spf: str = "unknown"
    dkim: str = "unknown"
    dmarc: str = "unknown"

    def all_fail(self) -> bool:
        return all(v == "fail" for v in (self.spf, self.dkim, self.dmarc))

    def any_fail(self) -> bool:
        return any(v == "fail" for v in (self.spf, self.dkim, self.dmarc))


@dataclass
class Hop:
    index: int
    from_host: str = ""
    from_ip: str = ""
    by_host: str = ""
    timestamp: Optional[datetime] = None
    raw: str = ""


@dataclass
class HeaderAnalysis:
    auth: AuthVerdict
    hops: list[Hop] = field(default_factory=list)
    timestamp_skew_seconds: Optional[int] = None
    anomalies: list[str] = field(default_factory=list)


def parse_auth_results(value: str) -> AuthVerdict:
    """Parse Authentication-Results header(s) for SPF/DKIM/DMARC verdicts."""
    verdict = AuthVerdict()
    if not value:
        return verdict
    lowered = value.lower()
    for mech, attr in (("spf", "spf"), ("dkim", "dkim"), ("dmarc", "dmarc")):
        m = re.search(rf"{mech}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", lowered)
        if m:
            setattr(verdict, attr, m.group(1))
    return verdict


def parse_received(received_headers: list[str]) -> list[Hop]:
    """Parse Received: headers into hops. Order = newest first (closest to recipient).

    We reverse so hop 1 = origin (sender) and the last hop = final recipient MTA.
    """
    hops: list[Hop] = []
    # Reverse so origin is first
    for idx, raw in enumerate(reversed(received_headers), start=1):
        flat = raw.replace("\n", " ").replace("\r", " ")
        hop = Hop(index=idx, raw=flat)
        if m := HOSTNAME_RE.search(flat):
            hop.from_host = m.group(1)
        if m := BY_RE.search(flat):
            hop.by_host = m.group(1)
        if m := IPV4_RE.search(flat):
            hop.from_ip = m.group(1)
        # Timestamp is after the last semicolon
        if ";" in flat:
            ts_part = flat.rsplit(";", 1)[1].strip()
            try:
                hop.timestamp = parsedate_to_datetime(ts_part)
            except (TypeError, ValueError):
                pass
        hops.append(hop)
    return hops


def detect_anomalies(hops: list[Hop]) -> tuple[Optional[int], list[str]]:
    """Detect timestamp skew and other oddities across hops."""
    anomalies: list[str] = []
    max_skew: Optional[int] = None

    timestamps = [h.timestamp for h in hops if h.timestamp is not None]
    if len(timestamps) >= 2:
        # Ensure tz-aware for comparison
        normalized = [t.astimezone(timezone.utc) if t.tzinfo else t.replace(tzinfo=timezone.utc) for t in timestamps]
        # The path should be monotonic forward in time; find biggest backward jump
        for prev, curr in zip(normalized, normalized[1:]):
            delta = (curr - prev).total_seconds()
            if delta < 0 and abs(delta) > 60:
                anomalies.append(
                    f"Backwards time travel between hops ({int(abs(delta))}s) -- possible header forgery"
                )
            if abs(delta) > max_skew if max_skew is not None else False:
                pass
        diffs = [abs((b - a).total_seconds()) for a, b in zip(normalized, normalized[1:])]
        if diffs:
            max_skew = int(max(diffs))
            if max_skew > 3600 * 6:
                anomalies.append(f"Large timestamp skew ({max_skew // 3600}h) -- likely clock mismatch or forgery")

    # Private IP origin = relayed-through, not necessarily bad but worth flagging if origin is internal
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
                        "127.")
    if hops and hops[0].from_ip and hops[0].from_ip.startswith(private_prefixes):
        anomalies.append(f"Origin IP {hops[0].from_ip} is RFC1918/private -- claimed origin may be spoofed")

    return max_skew, anomalies


def analyze(received_headers: list[str], auth_results: str) -> HeaderAnalysis:
    auth = parse_auth_results(auth_results)
    hops = parse_received(received_headers)
    skew, anomalies = detect_anomalies(hops)

    if auth.all_fail():
        anomalies.insert(0, "SPF, DKIM, and DMARC all FAIL -- unauthenticated mail")
    elif auth.any_fail():
        failed = [m for m in ("spf", "dkim", "dmarc") if getattr(auth, m) == "fail"]
        anomalies.insert(0, f"Authentication failure: {', '.join(f.upper() for f in failed)}")

    return HeaderAnalysis(auth=auth, hops=hops, timestamp_skew_seconds=skew, anomalies=anomalies)
