"""Optional API enrichment: VirusTotal, URLscan, AbuseIPDB.

All clients are no-ops when their API key is unset. The triage pipeline never
hard-fails on a missing key -- analysts can run the tool offline and still get
all the local checks (headers, URLs, attachments, lookalike, domain age).
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass, field
from typing import Optional

import requests


VT_BASE = "https://www.virustotal.com/api/v3"
URLSCAN_BASE = "https://urlscan.io/api/v1"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

TIMEOUT = 10.0


@dataclass
class EnrichmentResult:
    source: str
    verdict: str  # "malicious", "suspicious", "clean", "unknown", "error"
    detail: str = ""
    raw: dict = field(default_factory=dict)


def _vt_key() -> Optional[str]:
    return os.environ.get("VIRUSTOTAL_API_KEY") or None


def _urlscan_key() -> Optional[str]:
    return os.environ.get("URLSCAN_API_KEY") or None


def _abuseipdb_key() -> Optional[str]:
    return os.environ.get("ABUSEIPDB_API_KEY") or None


def vt_url(url: str) -> Optional[EnrichmentResult]:
    key = _vt_key()
    if not key:
        return None
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        r = requests.get(
            f"{VT_BASE}/urls/{url_id}",
            headers={"x-apikey": key},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return EnrichmentResult("VirusTotal", "unknown", "not yet analyzed")
        r.raise_for_status()
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        verdict = "malicious" if mal >= 3 else "suspicious" if (mal + susp) >= 1 else "clean"
        return EnrichmentResult("VirusTotal", verdict, f"{mal + susp}/{total} engines flagged", raw=stats)
    except requests.RequestException as e:
        return EnrichmentResult("VirusTotal", "error", str(e))


def vt_file(sha256: str) -> Optional[EnrichmentResult]:
    key = _vt_key()
    if not key:
        return None
    try:
        r = requests.get(
            f"{VT_BASE}/files/{sha256}",
            headers={"x-apikey": key},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return EnrichmentResult("VirusTotal", "unknown", "hash not seen by VT")
        r.raise_for_status()
        data = r.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        mal = stats.get("malicious", 0)
        susp = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        names = data.get("data", {}).get("attributes", {}).get("popular_threat_classification", {})
        label = names.get("suggested_threat_label", "")
        verdict = "malicious" if mal >= 3 else "suspicious" if (mal + susp) >= 1 else "clean"
        detail = f"{mal + susp}/{total} engines flagged"
        if label:
            detail += f" -- {label}"
        return EnrichmentResult("VirusTotal", verdict, detail, raw=stats)
    except requests.RequestException as e:
        return EnrichmentResult("VirusTotal", "error", str(e))


def urlscan_search(host: str) -> Optional[EnrichmentResult]:
    """Search urlscan.io for recent scans of this host."""
    key = _urlscan_key()
    headers = {"API-Key": key} if key else {}
    try:
        r = requests.get(
            f"{URLSCAN_BASE}/search/",
            params={"q": f"page.domain:{host}", "size": 5},
            headers=headers,
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        results = data.get("results", [])
        if not results:
            return EnrichmentResult("URLscan", "unknown", "no recent scans")
        malicious = sum(1 for x in results if x.get("verdicts", {}).get("overall", {}).get("malicious"))
        if malicious >= 1:
            return EnrichmentResult("URLscan", "malicious", f"{malicious}/{len(results)} scans flagged malicious")
        return EnrichmentResult("URLscan", "clean", f"{len(results)} scans, none flagged")
    except requests.RequestException as e:
        return EnrichmentResult("URLscan", "error", str(e))


def abuseipdb_ip(ip: str) -> Optional[EnrichmentResult]:
    key = _abuseipdb_key()
    if not key:
        return None
    try:
        r = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        reports = data.get("totalReports", 0)
        country = data.get("countryCode", "")
        verdict = "malicious" if score >= 75 else "suspicious" if score >= 25 else "clean"
        detail = f"confidence {score}% ({reports} reports"
        if country:
            detail += f", {country}"
        detail += ")"
        return EnrichmentResult("AbuseIPDB", verdict, detail, raw=data)
    except requests.RequestException as e:
        return EnrichmentResult("AbuseIPDB", "error", str(e))


def any_keys_set() -> bool:
    return bool(_vt_key() or _urlscan_key() or _abuseipdb_key())
