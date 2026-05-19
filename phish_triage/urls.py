"""URL extraction from body text + HTML, defanging, and shortener expansion."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup


URL_RE = re.compile(
    r"https?://[^\s<>\"'\)\]\}]+",
    re.IGNORECASE,
)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly", "is.gd",
    "rebrand.ly", "rb.gy", "cutt.ly", "shorturl.at", "tiny.cc", "soo.gd",
    "bl.ink", "lnkd.in", "trib.al",
}


@dataclass
class ExtractedURL:
    raw: str
    defanged: str
    host: str
    is_shortener: bool
    expanded: Optional[str] = None
    expanded_host: Optional[str] = None
    found_in: str = ""  # "text" or "html-href" or "html-text"


def defang(url: str) -> str:
    """Render a URL non-clickable using the SOC convention."""
    return (
        url.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace(".", "[.]")
    )


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _strip_trailing_punct(url: str) -> str:
    while url and url[-1] in ".,;:!?\")]}>":
        url = url[:-1]
    return url


def extract_urls(body_text: str, body_html: str) -> list[ExtractedURL]:
    """Extract URLs from both the plaintext and HTML parts. Dedupes by raw URL."""
    seen: dict[str, ExtractedURL] = {}

    for raw in URL_RE.findall(body_text or ""):
        raw = _strip_trailing_punct(raw)
        if raw and raw not in seen:
            host = _host(raw)
            seen[raw] = ExtractedURL(
                raw=raw,
                defanged=defang(raw),
                host=host,
                is_shortener=host in SHORTENERS,
                found_in="text",
            )

    if body_html:
        soup = BeautifulSoup(body_html, "html.parser")
        for a in soup.find_all("a", href=True):
            raw = _strip_trailing_punct(a["href"].strip())
            if raw.lower().startswith(("http://", "https://")) and raw not in seen:
                host = _host(raw)
                seen[raw] = ExtractedURL(
                    raw=raw,
                    defanged=defang(raw),
                    host=host,
                    is_shortener=host in SHORTENERS,
                    found_in="html-href",
                )
        # Also catch URLs that appear as visible text but not as hrefs
        text = soup.get_text(" ")
        for raw in URL_RE.findall(text):
            raw = _strip_trailing_punct(raw)
            if raw and raw not in seen:
                host = _host(raw)
                seen[raw] = ExtractedURL(
                    raw=raw,
                    defanged=defang(raw),
                    host=host,
                    is_shortener=host in SHORTENERS,
                    found_in="html-text",
                )

    return list(seen.values())


def expand_shorteners(urls: Iterable[ExtractedURL], timeout: float = 5.0) -> None:
    """Resolve shortened URLs in place via HEAD requests (no body downloaded)."""
    for u in urls:
        if not u.is_shortener:
            continue
        try:
            r = requests.head(u.raw, allow_redirects=True, timeout=timeout)
            final = r.url
            if final and final != u.raw:
                u.expanded = final
                u.expanded_host = _host(final)
        except requests.RequestException:
            pass
