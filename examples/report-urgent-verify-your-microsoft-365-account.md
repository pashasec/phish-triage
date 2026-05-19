# Phishing Triage Report -- Urgent: Verify your Microsoft 365 account

**Verdict:** CONFIRMED PHISHING  (score 140)

## Sender

- **From:** `billing@micros0ft-verify.com` (Microsoft 365 Security)
- **Reply-To:** `attacker@protonmail.com`  [!] mismatch with From
- **Return-Path:** `bounce@micros0ft-verify.com`
- **Date:** Mon, 18 May 2026 14:22:10 +0000
- **Message-ID:** `<CAJ7xy.2026051814.abc123@micros0ft-verify.com>`

## Sender Domain

- **Domain:** `micros0ft-verify.com`
- [!] **Lookalike of:** `microsoft` (edit distance 0)

## Authentication

- **SPF:** FAIL
- **DKIM:** FAIL
- **DMARC:** FAIL

## Hop Analysis

1. from `sender-relay.micros0ft-verify.com` [`185.220.101.42`] -> `mta-mail.suspicious-host.ru`  (2026-05-18T06:20:01+00:00)
2. from `mta-mail.suspicious-host.ru` [`45.142.214.99`] -> `mx.victim-corp.com`  (2026-05-18T14:22:11+00:00)

**Anomalies:**
- [!] SPF, DKIM, and DMARC all FAIL -- unauthenticated mail
- [!] Large timestamp skew (8h) -- likely clock mismatch or forgery

## URLs

- `hxxps://micros0ft-verify[.]com/login?u=user`  _(found in html-href)_
- [!] `hxxps://bit[.]ly/3xK9aZQ`  _(found in html-href)_
- `hxxps://legit-cdn[.]net/tracker[.]gif`  _(found in html-href)_

## Attachments

- **invoice.html** (text/html, 179 bytes)
    - SHA256: `d43e2d14ea747523ecc0c908ae1bc1848ceac7b4a267a81148220e8c70466ad0`
    - SHA1: `c6e43101aa5a9a1b41c9b6015b0318c43a622d67`
    - MD5: `e8dcba51e734283e32d8ce0b5e4be68a`
    - [!] HTML attachment -- classic credential-phish vector

## MITRE ATT&CK

- **T1566.001** -- Phishing: Spearphishing Attachment  _(Email carries one or more attachments)_
- **T1566.002** -- Phishing: Spearphishing Link  _(Email contains clickable URLs)_
- **T1566.001** -- Phishing: Spearphishing Attachment (HTML smuggling)  _(HTML attachment commonly used to deliver credential-harvest forms)_
- **T1583.001** -- Acquire Infrastructure: Domains  _(Sender domain appears to impersonate a known brand)_
- **T1534** -- Internal Spearphishing / Spoofing  _(Email failed SPF/DKIM/DMARC -- sender identity is unverified)_

## Verdict Detail

**Score:** 140

**Contributing signals:**
- All three auth checks (SPF/DKIM/DMARC) FAIL (+40)
- Sender domain looks like a known brand (+35)
- Reply-To domain differs from From domain (+15)
- 1 shortened URL(s) (+15)
- HTML attachment -- credential-phish vector (+25)
- Large timestamp skew across hops (+10)
