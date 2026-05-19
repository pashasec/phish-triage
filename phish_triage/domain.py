"""Domain analysis: registration age + lookalike detection against common brands."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import tldextract


# Brands phishers most commonly impersonate. Keep tight -- false positives on
# legitimate variations are worse than misses, since the verdict aggregates
# many signals.
COMMON_BRANDS = [
    "microsoft", "office365", "outlook", "google", "gmail", "apple", "icloud",
    "amazon", "paypal", "netflix", "facebook", "instagram", "linkedin",
    "dropbox", "docusign", "adobe", "github", "slack", "zoom", "spotify",
    "wellsfargo", "chase", "bankofamerica", "citibank", "fedex", "ups", "dhl",
    "usps", "irs", "hmrc", "ato", "stripe", "square", "venmo", "cashapp",
    "coinbase", "binance", "metamask", "twitter", "tiktok", "whatsapp",
]


@dataclass
class DomainAnalysis:
    domain: str
    registered_domain: str  # e.g. "micros0ft-verify.com"
    age_days: Optional[int] = None
    creation_date: Optional[str] = None
    registrar: Optional[str] = None
    lookalike_of: Optional[str] = None
    lookalike_distance: Optional[int] = None
    flags: list[str] = field(default_factory=list)


def _registered_domain(host: str) -> str:
    ext = tldextract.extract(host)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return host


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            ins = curr[j - 1] + 1
            dele = prev[j] + 1
            sub = prev[j - 1] + (ca != cb)
            curr.append(min(ins, dele, sub))
        prev = curr
    return prev[-1]


# Common homoglyph substitutions -- characters phishers swap to look similar.
HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
    "rn": "m",  # 'rn' visually resembles 'm'
    "vv": "w",
}


def _normalize_homoglyphs(s: str) -> str:
    out = s.lower()
    for bad, good in HOMOGLYPHS.items():
        out = out.replace(bad, good)
    return out


def detect_lookalike(domain: str) -> tuple[Optional[str], Optional[int]]:
    """Check if `domain` is a likely impersonation of a known brand.

    Returns (brand, edit_distance) if a match is found, else (None, None).
    """
    ext = tldextract.extract(domain)
    label = ext.domain.lower()
    if not label:
        return None, None

    # Exact match -> not a lookalike
    if label in COMMON_BRANDS:
        return None, None

    normalized = _normalize_homoglyphs(label)

    best_brand = None
    best_distance: Optional[int] = None
    for brand in COMMON_BRANDS:
        # Direct substring with a suspicious prefix/suffix
        if brand in label and brand != label:
            return brand, 0
        if brand in normalized and brand != normalized:
            return brand, 0
        # Short edit distance against brand
        dist = _levenshtein(normalized, brand)
        threshold = 2 if len(brand) >= 6 else 1
        if dist <= threshold and (best_distance is None or dist < best_distance):
            best_brand = brand
            best_distance = dist

    return best_brand, best_distance


def analyze_domain(host: str) -> DomainAnalysis:
    """Run age + lookalike checks on a hostname."""
    registered = _registered_domain(host)
    da = DomainAnalysis(domain=host, registered_domain=registered)

    brand, dist = detect_lookalike(registered)
    if brand:
        da.lookalike_of = brand
        da.lookalike_distance = dist
        # Lookalike is rendered as a dedicated line in the report; no duplicate flag.

    # Whois lookup -- best-effort, network-dependent
    try:
        import whois  # python-whois
        w = whois.whois(registered)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0] if creation else None
        if isinstance(creation, datetime):
            now = datetime.now(timezone.utc)
            ts = creation if creation.tzinfo else creation.replace(tzinfo=timezone.utc)
            da.age_days = (now - ts).days
            da.creation_date = ts.date().isoformat()
            if da.age_days is not None and da.age_days < 30:
                da.flags.append(f"newly registered domain ({da.age_days}d old)")
            elif da.age_days is not None and da.age_days < 180:
                da.flags.append(f"young domain ({da.age_days}d old)")
        if w.registrar:
            da.registrar = w.registrar if isinstance(w.registrar, str) else str(w.registrar)
    except Exception:
        # whois servers are flaky and rate-limit aggressively; never fail the run
        pass

    return da
