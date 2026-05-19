"""Smoke tests covering the end-to-end pipeline with bundled fixtures."""

from __future__ import annotations

from pathlib import Path

from phish_triage.attachments import hash_attachments
from phish_triage.domain import _levenshtein, detect_lookalike
from phish_triage.headers import analyze, parse_auth_results
from phish_triage.parser import parse_eml
from phish_triage.urls import defang, extract_urls
from phish_triage.verdict import score_email


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_phish_eml():
    p = parse_eml(FIXTURES / "sample-phish.eml")
    assert p.subject == "Urgent: Verify your Microsoft 365 account"
    assert p.from_addr == "billing@micros0ft-verify.com"
    assert p.reply_to == "attacker@protonmail.com"
    assert len(p.received_headers) == 2
    assert len(p.attachments) == 1
    assert p.attachments[0].filename == "invoice.html"


def test_auth_results_parsing():
    v = parse_auth_results("spf=fail; dkim=fail; dmarc=fail")
    assert v.all_fail()
    v2 = parse_auth_results("spf=pass; dkim=pass; dmarc=pass")
    assert not v2.any_fail()


def test_header_analysis_flags_failures():
    p = parse_eml(FIXTURES / "sample-phish.eml")
    h = analyze(p.received_headers, p.auth_results)
    assert h.auth.all_fail()
    assert any("FAIL" in a for a in h.anomalies)


def test_url_extraction_and_defang():
    p = parse_eml(FIXTURES / "sample-phish.eml")
    urls = extract_urls(p.body_text, p.body_html)
    hosts = {u.host for u in urls}
    assert "micros0ft-verify.com" in hosts
    assert "bit.ly" in hosts
    assert any(u.is_shortener for u in urls)
    assert defang("https://example.com/path") == "hxxps://example[.]com/path"


def test_attachment_hashing_flags_html():
    p = parse_eml(FIXTURES / "sample-phish.eml")
    hashed = hash_attachments(p.attachments)
    assert len(hashed) == 1
    a = hashed[0]
    assert len(a.sha256) == 64
    assert any("HTML attachment" in f for f in a.risk_flags)


def test_lookalike_detection():
    brand, dist = detect_lookalike("micros0ft-verify.com")
    assert brand == "microsoft"
    assert dist is not None


def test_levenshtein():
    assert _levenshtein("abc", "abc") == 0
    assert _levenshtein("kitten", "sitting") == 3


def test_verdict_phish_scored_high():
    v = score_email(
        auth_all_fail=True,
        auth_any_fail=True,
        lookalike_domain=True,
        newly_registered=True,
        young_domain=False,
        reply_to_mismatch=True,
        shortened_urls=1,
        dangerous_attachment=False,
        macro_attachment=False,
        html_attachment=True,
        external_malicious_hits=0,
        external_suspicious_hits=0,
        timestamp_skew_large=True,
    )
    assert v.severity == "confirmed-phishing"
    assert v.score >= 80


def test_verdict_clean_passes_through():
    v = score_email(
        auth_all_fail=False,
        auth_any_fail=False,
        lookalike_domain=False,
        newly_registered=False,
        young_domain=False,
        reply_to_mismatch=False,
        shortened_urls=0,
        dangerous_attachment=False,
        macro_attachment=False,
        html_attachment=False,
        external_malicious_hits=0,
        external_suspicious_hits=0,
        timestamp_skew_large=False,
    )
    assert v.severity == "clean"


def test_parse_clean_eml():
    p = parse_eml(FIXTURES / "sample-clean.eml")
    assert p.from_addr == "noreply@github.com"
    h = analyze(p.received_headers, p.auth_results)
    assert not h.auth.any_fail()
