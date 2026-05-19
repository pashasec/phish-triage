"""phish-triage CLI -- one command from .eml to incident report."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .attachments import hash_attachments
from .domain import analyze_domain
from .enrich import (
    EnrichmentResult,
    abuseipdb_ip,
    any_keys_set,
    urlscan_search,
    vt_file,
    vt_url,
)
from .headers import analyze
from .mitre import map_techniques
from .parser import parse_eml
from .report import SEVERITY_BADGE, TriageBundle, render_iocs_csv, render_markdown
from .urls import expand_shorteners, extract_urls
from .verdict import score_email


app = typer.Typer(
    add_completion=False,
    help="Turn a .eml file into a complete phishing incident report.",
    no_args_is_help=True,
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"phish-triage {__version__}")
        raise typer.Exit()


def _safe_slug(text: str, fallback: str) -> str:
    text = text.strip().lower() or fallback
    text = re.sub(r"[^a-z0-9]+", "-", text)[:60].strip("-")
    return text or fallback


def _print_summary(b: TriageBundle, eml_path: Path) -> None:
    badge = SEVERITY_BADGE[b.verdict.severity]
    console.print()
    console.print(Panel.fit(
        f"[bold]{eml_path.name}[/bold]\n[bold]Subject:[/bold] {b.email.subject or '(no subject)'}\n[bold]Verdict:[/bold] {badge}  (score {b.verdict.score})",
        title="phish-triage",
        border_style="cyan",
    ))

    sender = Table(show_header=False, box=None, padding=(0, 1))
    sender.add_row("[bold]From[/bold]", b.email.from_addr or "--")
    if b.email.reply_to and b.email.reply_to != b.email.from_addr:
        sender.add_row("[bold]Reply-To[/bold]", f"{b.email.reply_to}  [yellow][!] mismatch[/yellow]")
    sender.add_row("[bold]SPF/DKIM/DMARC[/bold]",
                   f"{b.headers.auth.spf.upper()} / {b.headers.auth.dkim.upper()} / {b.headers.auth.dmarc.upper()}")
    sd = b.sender_domain
    domain_line = f"`{sd.registered_domain}`"
    if sd.age_days is not None:
        domain_line += f" -- {sd.age_days}d old"
    if sd.lookalike_of:
        domain_line += f"  [yellow][!] lookalike of {sd.lookalike_of}[/yellow]"
    sender.add_row("[bold]Domain[/bold]", domain_line)
    console.print(sender)

    if b.headers.anomalies:
        console.print()
        console.print("[bold yellow]Anomalies:[/bold yellow]")
        for a in b.headers.anomalies:
            console.print(f"  [!] {a}")

    if b.urls:
        console.print()
        console.print(f"[bold]URLs ({len(b.urls)}):[/bold]")
        for u in b.urls[:10]:
            tag = " [yellow](shortener)[/yellow]" if u.is_shortener else ""
            line = f"  {u.defanged}{tag}"
            if u.expanded:
                line += f"  -> {u.expanded}"
            console.print(line)
        if len(b.urls) > 10:
            console.print(f"  ... and {len(b.urls) - 10} more (full list in report)")

    if b.attachments:
        console.print()
        console.print(f"[bold]Attachments ({len(b.attachments)}):[/bold]")
        for a in b.attachments:
            flags = ", ".join(a.risk_flags) if a.risk_flags else ""
            flag_text = f"  [yellow][!] {flags}[/yellow]" if flags else ""
            console.print(f"  {a.filename}  ({a.size}B)  sha256={a.sha256[:16]}...{flag_text}")

    if b.techniques:
        console.print()
        console.print("[bold]MITRE ATT&CK:[/bold]")
        for t in b.techniques:
            console.print(f"  {t.tid}  {t.name}")

    console.print()


@app.command()
def triage(
    eml: Path = typer.Argument(..., exists=True, dir_okay=False, readable=True, help="Path to .eml file"),
    out_dir: Path = typer.Option(Path("."), "--out", "-o", help="Directory for the report and IOC CSV"),
    expand_shortened: bool = typer.Option(True, "--expand/--no-expand", help="Expand shortened URLs via HEAD"),
    enrich: bool = typer.Option(True, "--enrich/--no-enrich", help="Run external API enrichment when keys are set"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress the terminal summary"),
    _version: bool = typer.Option(
        False, "--version", callback=_version_callback, is_eager=True, help="Show version and exit"
    ),
) -> None:
    """Triage a single .eml file end-to-end."""
    parsed = parse_eml(eml)

    header_analysis = analyze(parsed.received_headers, parsed.auth_results)

    sender_host = parsed.from_addr.split("@", 1)[1] if "@" in parsed.from_addr else ""
    sender_domain = analyze_domain(sender_host) if sender_host else analyze_domain("")

    urls = extract_urls(parsed.body_text, parsed.body_html)
    if expand_shortened:
        expand_shorteners(urls)

    hashed = hash_attachments(parsed.attachments)

    enrichments: dict[str, list[EnrichmentResult]] = {}
    external_mal = 0
    external_susp = 0
    if enrich and any_keys_set():
        seen_hosts: set[str] = set()
        for u in urls:
            if u.host and u.host not in seen_hosts:
                seen_hosts.add(u.host)
                for fn in (lambda h=u.host: urlscan_search(h),):
                    res = fn()
                    if res:
                        enrichments.setdefault(u.host, []).append(res)
                        if res.verdict == "malicious":
                            external_mal += 1
                        elif res.verdict == "suspicious":
                            external_susp += 1
            res = vt_url(u.raw)
            if res:
                enrichments.setdefault(u.raw, []).append(res)
                if res.verdict == "malicious":
                    external_mal += 1
                elif res.verdict == "suspicious":
                    external_susp += 1
        for hop in header_analysis.hops:
            if hop.from_ip:
                res = abuseipdb_ip(hop.from_ip)
                if res:
                    enrichments.setdefault(hop.from_ip, []).append(res)
                    if res.verdict == "malicious":
                        external_mal += 1
                    elif res.verdict == "suspicious":
                        external_susp += 1
        for a in hashed:
            res = vt_file(a.sha256)
            if res:
                enrichments.setdefault(a.sha256, []).append(res)
                if res.verdict == "malicious":
                    external_mal += 1
                elif res.verdict == "suspicious":
                    external_susp += 1
    elif enrich and not any_keys_set():
        console.print("[dim]No API keys set -- running offline checks only. See .env.example.[/dim]")

    has_url = bool(urls)
    has_attachment = bool(hashed)
    has_dangerous = any("dangerous executable" in f for a in hashed for f in a.risk_flags)
    has_macro = any("macro-enabled" in f for a in hashed for f in a.risk_flags)
    has_archive = any("archive may contain" in f for a in hashed for f in a.risk_flags)
    has_html_att = any("HTML attachment" in f for a in hashed for f in a.risk_flags)
    techniques = map_techniques(
        has_url=has_url,
        has_attachment=has_attachment,
        has_dangerous_attachment=has_dangerous,
        has_macro_doc=has_macro,
        has_archive=has_archive,
        has_html_attachment=has_html_att,
        has_lookalike=bool(sender_domain.lookalike_of),
        auth_failed=header_analysis.auth.any_fail(),
    )

    verdict = score_email(
        auth_all_fail=header_analysis.auth.all_fail(),
        auth_any_fail=header_analysis.auth.any_fail(),
        lookalike_domain=bool(sender_domain.lookalike_of),
        newly_registered=sender_domain.age_days is not None and sender_domain.age_days < 30,
        young_domain=sender_domain.age_days is not None and 30 <= sender_domain.age_days < 180,
        reply_to_mismatch=bool(parsed.reply_to and parsed.reply_to != parsed.from_addr),
        shortened_urls=sum(1 for u in urls if u.is_shortener),
        dangerous_attachment=has_dangerous,
        macro_attachment=has_macro,
        html_attachment=has_html_att,
        external_malicious_hits=external_mal,
        external_suspicious_hits=external_susp,
        timestamp_skew_large=header_analysis.timestamp_skew_seconds is not None
        and header_analysis.timestamp_skew_seconds > 3600 * 6,
    )

    bundle = TriageBundle(
        email=parsed,
        headers=header_analysis,
        sender_domain=sender_domain,
        urls=urls,
        attachments=hashed,
        enrichments=enrichments,
        techniques=techniques,
        verdict=verdict,
    )

    out_dir.mkdir(parents=True, exist_ok=True)
    slug = _safe_slug(parsed.subject, eml.stem)
    md_path = out_dir / f"report-{slug}.md"
    csv_path = out_dir / f"iocs-{slug}.csv"
    md_path.write_text(render_markdown(bundle), encoding="utf-8")
    csv_path.write_text(render_iocs_csv(bundle), encoding="utf-8")

    if not quiet:
        _print_summary(bundle, eml)

    console.print(f"[green]OK[/green] report -> {md_path}")
    console.print(f"[green]OK[/green] iocs   -> {csv_path}")

    if verdict.severity in ("likely-phishing", "confirmed-phishing"):
        sys.exit(2)


if __name__ == "__main__":
    app()
