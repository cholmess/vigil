"""Vigil CLI — unified LLM production safety platform commands."""

from __future__ import annotations

import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from vigil.config import VigilConfig
from vigil.forensics.engine import VigilForensicsWrapper
from vigil.loop.library import (
    import_attacks,
    import_community_attacks,
    list_attacks,
)
from vigil.loop.replayer import VigilBreakPointRunner

# --------------------------------------------------------------------------- #
# Top-level app                                                                #
# --------------------------------------------------------------------------- #

app = typer.Typer(
    name="vigil",
    help=(
        "LLM Production Safety Platform.\n\n"
        "Reads defaults from .vigil.yml in the current directory. "
        "CLI flags always override config values."
    ),
    no_args_is_help=True,
)

# --------------------------------------------------------------------------- #
# vigil network  (sub-app)                                                    #
# --------------------------------------------------------------------------- #

network_app = typer.Typer(
    name="network",
    help="Sync attack snapshots from the Vigil network.",
    no_args_is_help=True,
)
app.add_typer(network_app, name="network")

# --------------------------------------------------------------------------- #
# vigil forensics  (sub-app)                                                  #
# --------------------------------------------------------------------------- #

forensics_app = typer.Typer(
    name="forensics",
    help="Scan historical LLM logs for past breaches.",
    no_args_is_help=True,
)
app.add_typer(forensics_app, name="forensics")

# --------------------------------------------------------------------------- #
# vigil forensics audit  (nested sub-app)                                     #
# --------------------------------------------------------------------------- #

audit_app = typer.Typer(
    name="audit",
    help="Staged multi-source audit workflow.",
    no_args_is_help=True,
)
forensics_app.add_typer(audit_app, name="audit")

# --------------------------------------------------------------------------- #
# Shared helpers                                                               #
# --------------------------------------------------------------------------- #

_SEP = "━" * 42

_SCAN_STORE = Path(".vigil-data/scans")


class LogFormat(str, Enum):
    otel   = "otel"
    mlflow = "mlflow"
    jsonl  = "jsonl"      # alias → otel parser for now
    langsmith = "langsmith"  # alias → otel parser for now


def _status_color(status: str) -> str:
    colors = {"ALLOW": "green", "WARN": "yellow", "BLOCK": "red"}
    return typer.style(f"[{status:<5}]", fg=colors.get(status, "white"), bold=True)


def _echo_sep(title: str = "") -> None:
    if title:
        pad = max(0, 42 - len(title) - 2)
        typer.echo(f"{'━' * 2} {title} {'━' * pad}")
    else:
        typer.echo(_SEP)


def _source_label(from_config: bool) -> str:
    return typer.style(" (from .vigil.yml)", fg="cyan") if from_config else ""


def _resolve_path(
    cli_value: Path | None,
    config_value: Path | None,
    builtin_default: Path,
) -> tuple[Path, bool]:
    if cli_value is not None:
        return cli_value, False
    if config_value is not None:
        return config_value, True
    return builtin_default, False


def _normalise_format(fmt: str) -> str:
    """Normalise format aliases to the canonical parser keys used by the engine."""
    mapping = {
        "jsonl": "jsonl",
        "openai": "jsonl",
        "anthropic": "jsonl",
        "langsmith": "langsmith",
        "langfuse": "langfuse",
        "plain": "plain",
        "text": "plain",
        "otel": "otel",
        "mlflow": "mlflow",
        "otlp": "otel",
        "otlp-json": "otel",
    }
    return mapping.get(fmt, fmt)


def _parse_iso8601(value: str) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if raw.endswith("Z"):
        raw = raw[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _relative_ago(value: str) -> str:
    ts = _parse_iso8601(value)
    if ts is None:
        return "unknown time"
    now = datetime.now(timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    delta = now - ts.astimezone(timezone.utc)
    seconds = int(max(0, delta.total_seconds()))
    days = seconds // 86400
    if days > 0:
        return f"{days} day{'s' if days != 1 else ''} ago"
    hours = seconds // 3600
    if hours > 0:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    minutes = seconds // 60
    if minutes > 0:
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    return "just now"


def _truncate(text: str, max_len: int = 92) -> str:
    compact = " ".join((text or "").split())
    if len(compact) <= max_len:
        return compact
    return compact[: max_len - 3] + "..."


def _format_snapshot_display(path: str | Path, attacks_dir: Path) -> str:
    p = Path(path)
    try:
        return p.relative_to(Path.cwd()).as_posix()
    except ValueError:
        try:
            rel = p.relative_to(attacks_dir)
            return f"{attacks_dir.name}/{rel.as_posix()}"
        except ValueError:
            return f"{attacks_dir.name}/{p.name}"


def _display_attacks_dir(attacks_dir: Path) -> str:
    try:
        return attacks_dir.relative_to(Path.cwd()).as_posix().rstrip("/") + "/"
    except ValueError:
        return f"{attacks_dir.name}/"


def _load_scan(scan_id: str) -> dict:
    path = _SCAN_STORE / f"{scan_id}.json"
    if not path.exists():
        typer.echo(typer.style(f"Error: scan '{scan_id}' not found at {path}", fg="red"), err=True)
        raise typer.Exit(code=2)
    return json.loads(path.read_text(encoding="utf-8"))


def _save_scan(scan_id: str, payload: dict) -> Path:
    _SCAN_STORE.mkdir(parents=True, exist_ok=True)
    path = _SCAN_STORE / f"{scan_id}.json"
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path


def _build_test_report(summary: dict) -> dict:
    total = int(summary.get("total", 0))
    allowed = int(summary.get("allowed", 0))
    warned = int(summary.get("warned", 0))
    blocked = int(summary.get("blocked", 0))
    errors = int(summary.get("errors", 0))
    results = list(summary.get("results", []))

    denominator = total if total > 0 else 1
    shield_pct = round((allowed / denominator) * 100, 2)

    severity_counts = Counter(r.get("severity", "unknown") for r in results)
    technique_counts = Counter(r.get("technique", "unknown") for r in results)

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "shield_score": {
            "blocked_attacks": allowed,
            "total_attacks": total,
            "percent": shield_pct,
        },
        "summary": {
            "total": total,
            "allowed": allowed,
            "warned": warned,
            "blocked": blocked,
            "errors": errors,
        },
        "breakdown": {
            "by_severity": dict(sorted(severity_counts.items())),
            "by_technique": dict(sorted(technique_counts.items())),
        },
        "results": results,
    }


def _write_test_report(path: Path, summary: dict) -> Path:
    payload = _build_test_report(summary)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


# --------------------------------------------------------------------------- #
# vigil forensics scan                                                         #
# --------------------------------------------------------------------------- #

@forensics_app.command("scan")
def forensics_scan(
    logs: Optional[Path] = typer.Option(
        None, "--logs",
        help="Path to a log file or directory. Falls back to forensics.log_dir in .vigil.yml.",
        show_default=False,
    ),
    format: Optional[LogFormat] = typer.Option(
        None, "--format",
        help="Log format: otel (default), mlflow, jsonl, langsmith.",
        show_default=False,
    ),
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help="Directory for .bp.json snapshots. Falls back to paths.attacks in .vigil.yml.",
        show_default=False,
    ),
    registry: Optional[Path] = typer.Option(
        None, "--registry",
        help="Path to Canari .db to pull canary token patterns from (future support).",
        show_default=False,
    ),
    since: Optional[str] = typer.Option(
        None, "--since", metavar="YYYY-MM-DD",
        help="Only scan log files modified on or after this date (directory scans).",
        show_default=False,
    ),
    until: Optional[str] = typer.Option(
        None, "--until", metavar="YYYY-MM-DD",
        help="Only scan log files modified before this date (directory scans).",
        show_default=False,
    ),
) -> None:
    """Scan historical LLM logs for past breaches and export each finding as a .bp.json snapshot.

    Prints a scan ID you can use with the other `vigil forensics` commands.
    """
    cfg = VigilConfig.load()

    effective_attacks, attacks_from_cfg = _resolve_path(
        attacks_dir, cfg.paths.attacks, Path("./tests/attacks")
    )

    if logs is not None:
        effective_logs: Path = logs
        logs_from_cfg = False
    elif cfg.forensics.log_dir is not None:
        effective_logs = cfg.forensics.log_dir
        logs_from_cfg = True
    else:
        typer.echo(
            typer.style("Error: --logs is required (or set forensics.log_dir in .vigil.yml).", fg="red"),
            err=True,
        )
        raise typer.Exit(code=2)

    if not effective_logs.exists():
        typer.echo(typer.style(f"Error: log path does not exist: {effective_logs}", fg="red"), err=True)
        raise typer.Exit(code=2)

    raw_format = format.value if format is not None else (cfg.forensics.format or "otel")
    effective_format = _normalise_format(raw_format)
    format_from_cfg = format is None and bool(cfg.forensics.format)

    _echo_sep("Vigil Forensic Scan")
    typer.echo(f"  Log path:    {effective_logs}{_source_label(logs_from_cfg)}")
    typer.echo(f"  Format:      {raw_format}{_source_label(format_from_cfg)}")
    typer.echo(f"  Attacks dir: {effective_attacks}{_source_label(attacks_from_cfg)}")
    _echo_sep()

    wrapper = VigilForensicsWrapper()
    try:
        summary = wrapper.run_audit(effective_logs, effective_format, attacks_dir=effective_attacks)
    except Exception as exc:
        typer.echo(typer.style(f"Error running scan: {exc}", fg="red", bold=True), err=True)
        raise typer.Exit(code=2)

    scan_id = str(uuid.uuid4())
    scan_record = {
        "scan_id": scan_id,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "log_path": str(effective_logs),
        "format": raw_format,
        "attacks_dir": str(effective_attacks),
        "turns_parsed": summary["turns_parsed"],
        "findings_count": summary["findings"],
        "finding_details": summary.get("finding_details", []),
        "snapshots": summary["saved"],
        "errors": summary["errors"],
    }
    _save_scan(scan_id, scan_record)

    typer.echo(f"  Turns parsed:  {summary['turns_parsed']}")
    typer.echo(f"  Findings:      {summary['findings']}")
    typer.echo(f"  Errors:        {summary['errors']}")
    typer.echo(f"  Scan ID:       {typer.style(scan_id, fg='cyan')}")
    typer.echo("")

    finding_details = summary.get("finding_details", [])
    if summary["saved"] and finding_details:
        typer.echo(typer.style("  INCIDENTS FOUND:", fg="red", bold=True) + f" {summary['findings']}")
        typer.echo("")
        for finding in finding_details:
            sev = str(finding.get("severity", "UNKNOWN")).upper()
            color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "green"}.get(sev, "white")
            pattern = str(finding.get("pattern_id", "unknown"))
            ago = _relative_ago(str(finding.get("timestamp", "")))
            snippet = _truncate(str(finding.get("context", "")))
            typer.echo(f"  {typer.style(sev, fg=color, bold=True)} — {pattern}")
            typer.echo(f"    {ago}")
            if snippet:
                typer.echo(f"    Context: \"{snippet}\"")
            typer.echo("")

        typer.echo("  These incidents occurred before you were monitoring.")
        typer.echo(f"  Exported as BreakPoint snapshots → {_display_attacks_dir(effective_attacks)}")
        typer.echo("")
        for path in summary["saved"]:
            typer.echo(f"  → {_format_snapshot_display(path, effective_attacks)}")
    else:
        typer.echo(typer.style("  No findings — logs appear clean.", fg="green"))

    _echo_sep()

    if summary["findings"] > 0:
        typer.echo(
            typer.style(
                f"\n  {summary['findings']} snapshot(s) saved to {effective_attacks}.\n"
                f"  Run `vigil forensics summary --scan-id {scan_id}` to inspect.\n"
                f"  Run `vigil test --attacks-dir {effective_attacks} --prompt-file <file>` "
                "to check your current prompt.\n",
                fg="yellow",
            )
        )
    else:
        typer.echo("")


# --------------------------------------------------------------------------- #
# vigil forensics summary                                                      #
# --------------------------------------------------------------------------- #

@forensics_app.command("summary")
def forensics_summary(
    scan_id: str = typer.Option(..., "--scan-id", help="Scan ID returned by `vigil forensics scan`."),
) -> None:
    """Print a summary of a completed forensic scan."""
    record = _load_scan(scan_id)

    _echo_sep("Forensic Scan Summary")
    typer.echo(f"  Scan ID:      {record['scan_id']}")
    typer.echo(f"  Scanned at:   {record['scanned_at']}")
    typer.echo(f"  Log path:     {record['log_path']}")
    typer.echo(f"  Format:       {record['format']}")
    typer.echo(f"  Turns parsed: {record['turns_parsed']}")
    typer.echo(f"  Findings:     {record['findings_count']}")
    typer.echo(f"  Errors:       {record['errors']}")
    _echo_sep()

    snapshots = record.get("snapshots", [])
    if snapshots:
        typer.echo(f"  Snapshots ({len(snapshots)}):")
        for p in snapshots:
            typer.echo(f"    {typer.style('✓', fg='green')} {p}")
    else:
        typer.echo(typer.style("  No findings in this scan.", fg="green"))
    typer.echo("")


# --------------------------------------------------------------------------- #
# vigil forensics matches                                                      #
# --------------------------------------------------------------------------- #

@forensics_app.command("matches")
def forensics_matches(
    scan_id: str = typer.Option(..., "--scan-id", help="Scan ID returned by `vigil forensics scan`."),
    tier: Optional[str] = typer.Option(
        None, "--tier",
        help="Filter by finding kind, e.g. 'real_credential_leak', 'canary_token_leak', 'pii_leak'.",
    ),
) -> None:
    """List individual match snapshots from a completed scan, optionally filtered by tier/kind."""
    record = _load_scan(scan_id)
    snapshots: list[str] = record.get("snapshots", [])

    if not snapshots:
        typer.echo(typer.style("No findings in this scan.", fg="green"))
        return

    _echo_sep(f"Matches — scan {scan_id[:8]}…")
    shown = 0
    for snap_path in snapshots:
        p = Path(snap_path)
        if not p.exists():
            continue
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            continue

        token_type = data.get("canary", {}).get("token_type", "unknown")
        severity = data.get("metadata", {}).get("severity", "?")
        source_type = data.get("forensics", {}).get("source_type", "?")
        kind = token_type  # pattern_id is stored as token_type in forensics snapshots

        if tier and tier.lower() not in kind.lower() and tier.lower() not in source_type.lower():
            continue

        typer.echo(f"  {typer.style(severity, fg='red' if severity == 'CRITICAL' else 'yellow')}  {p.name}  [{token_type}]")
        shown += 1

    _echo_sep()
    typer.echo(f"  Shown: {shown} of {len(snapshots)} snapshots")
    if tier:
        typer.echo(f"  Filter: --tier {tier}")
    typer.echo("")


# --------------------------------------------------------------------------- #
# vigil forensics evidence-pack                                                #
# --------------------------------------------------------------------------- #

@forensics_app.command("evidence-pack")
def forensics_evidence_pack(
    scan_id: str = typer.Option(..., "--scan-id", help="Scan ID returned by `vigil forensics scan`."),
    out: Path = typer.Option(..., "--out", help="Output path for the evidence JSON file."),
) -> None:
    """Build a compliance evidence pack from a completed scan and write it to disk."""
    record = _load_scan(scan_id)
    snapshots: list[str] = record.get("snapshots", [])

    findings = []
    for snap_path in snapshots:
        p = Path(snap_path)
        if p.exists():
            try:
                findings.append(json.loads(p.read_text(encoding="utf-8")))
            except Exception:
                pass

    pack = {
        "vigil_version": "0.1.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "scan_id": scan_id,
        "log_path": record["log_path"],
        "scanned_at": record["scanned_at"],
        "turns_analyzed": record["turns_parsed"],
        "findings_count": record["findings_count"],
        "findings": findings,
        "methodology": {
            "detector": "Vigil deterministic pattern matching (Tier 1–3)",
            "llm_calls": False,
        },
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(pack, indent=2, default=str), encoding="utf-8")

    typer.echo(typer.style(f"✓ Evidence pack written to {out}", fg="green"))
    typer.echo(f"  Findings: {record['findings_count']}")


# --------------------------------------------------------------------------- #
# vigil forensics export-attacks                                               #
# --------------------------------------------------------------------------- #

@forensics_app.command("export-attacks")
def forensics_export_attacks(
    scan_id: str = typer.Option(..., "--scan-id", help="Scan ID returned by `vigil forensics scan`."),
    out: Path = typer.Option(..., "--out", help="Directory to write .bp.json snapshots into."),
) -> None:
    """Copy or re-export all .bp.json snapshots from a scan to a target directory."""
    import shutil

    record = _load_scan(scan_id)
    snapshots: list[str] = record.get("snapshots", [])

    out.mkdir(parents=True, exist_ok=True)
    copied = 0

    for snap_path in snapshots:
        src = Path(snap_path)
        if src.exists():
            dest = out / src.name
            shutil.copy2(src, dest)
            typer.echo(f"  {typer.style('✓', fg='green')} {dest}")
            copied += 1

    typer.echo("")
    typer.echo(typer.style(f"Exported {copied} snapshot(s) to {out}", fg="green" if copied else "yellow"))
    if copied:
        typer.echo(f"  Run `vigil test --attacks-dir {out} --prompt-file <file>` to replay them.")


# --------------------------------------------------------------------------- #
# vigil forensics audit init                                                   #
# --------------------------------------------------------------------------- #

@audit_app.command("init")
def audit_init(
    name: str = typer.Option("default", "--name", help="Human-readable name for this audit."),
    client: str = typer.Option("unknown", "--client", help="Client / company name."),
    application: str = typer.Option("unknown", "--application", help="Application being audited."),
) -> None:
    """Initialise a new staged audit workspace under .vigil-data/audits/."""
    audit_id = f"audit-{name.lower().replace(' ', '-')}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
    audit_dir = Path(".vigil-data/audits") / audit_id
    audit_dir.mkdir(parents=True, exist_ok=True)

    meta = {
        "audit_id": audit_id,
        "name": name,
        "client": client,
        "application": application,
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sources": [],
        "status": "init",
    }
    (audit_dir / "metadata.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    typer.echo(typer.style(f"✓ Audit workspace created: {audit_dir}", fg="green"))
    typer.echo(f"  Audit ID: {typer.style(audit_id, fg='cyan')}")
    typer.echo(f"\n  Next: vigil forensics audit ingest --audit-id {audit_id} --source ./logs/ --label Production")


# --------------------------------------------------------------------------- #
# vigil forensics audit ingest                                                 #
# --------------------------------------------------------------------------- #

@audit_app.command("ingest")
def audit_ingest(
    audit_id: str = typer.Option(..., "--audit-id", help="Audit ID from `vigil forensics audit init`."),
    source: Path = typer.Option(..., "--source", help="Log file or directory to ingest."),
    label: str = typer.Option("unlabelled", "--label", help="Human-readable label for this source."),
    format: Optional[LogFormat] = typer.Option(None, "--format", help="Log format (default: otel)."),
) -> None:
    """Ingest a log source into an existing audit workspace."""
    audit_dir = Path(".vigil-data/audits") / audit_id
    meta_path = audit_dir / "metadata.json"

    if not meta_path.exists():
        typer.echo(typer.style(f"Error: audit '{audit_id}' not found at {audit_dir}", fg="red"), err=True)
        raise typer.Exit(code=2)

    if not source.exists():
        typer.echo(typer.style(f"Error: source path does not exist: {source}", fg="red"), err=True)
        raise typer.Exit(code=2)

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    fmt = _normalise_format(format.value if format else "otel")

    source_entry = {
        "label": label,
        "path": str(source),
        "format": fmt,
        "ingested_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    meta.setdefault("sources", []).append(source_entry)
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    typer.echo(typer.style(f"✓ Ingested: {source} [{label}]", fg="green"))
    typer.echo(f"  Total sources: {len(meta['sources'])}")
    typer.echo(f"\n  Next: vigil forensics audit scan --audit-id {audit_id}")


# --------------------------------------------------------------------------- #
# vigil forensics audit scan                                                   #
# --------------------------------------------------------------------------- #

@audit_app.command("scan")
def audit_scan(
    audit_id: str = typer.Option(..., "--audit-id", help="Audit ID from `vigil forensics audit init`."),
) -> None:
    """Run the forensic scan across all ingested sources in the audit workspace."""
    audit_dir = Path(".vigil-data/audits") / audit_id
    meta_path = audit_dir / "metadata.json"

    if not meta_path.exists():
        typer.echo(typer.style(f"Error: audit '{audit_id}' not found.", fg="red"), err=True)
        raise typer.Exit(code=2)

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    sources = meta.get("sources", [])
    if not sources:
        typer.echo(typer.style("Error: no sources ingested yet. Run `vigil forensics audit ingest` first.", fg="red"), err=True)
        raise typer.Exit(code=2)

    attacks_dir = audit_dir / "attacks"
    wrapper = VigilForensicsWrapper()
    total_turns = 0
    total_findings = 0
    all_snapshots: list[str] = []

    _echo_sep(f"Audit Scan — {audit_id}")
    for src in sources:
        log_path = Path(src["path"])
        if not log_path.exists():
            typer.echo(typer.style(f"  [SKIP] {log_path} — not found", fg="yellow"))
            continue

        typer.echo(f"  Scanning: {log_path} [{src['label']}]")
        try:
            summary = wrapper.run_audit(log_path, src["format"], attacks_dir=attacks_dir)
            total_turns += summary["turns_parsed"]
            total_findings += summary["findings"]
            all_snapshots.extend(summary["saved"])
        except Exception as exc:
            typer.echo(typer.style(f"    Error: {exc}", fg="red"))

    _echo_sep()
    typer.echo(f"  Turns scanned:  {total_turns}")
    typer.echo(f"  Findings:       {total_findings}")

    meta["scan_results"] = {
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "turns_scanned": total_turns,
        "findings": total_findings,
        "snapshots": all_snapshots,
    }
    meta["status"] = "scanned"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if total_findings > 0:
        typer.echo(
            typer.style(
                f"\n  {total_findings} finding(s). "
                f"Run `vigil forensics audit report --audit-id {audit_id}` to generate a report.\n",
                fg="yellow",
            )
        )
    else:
        typer.echo(typer.style("\n  No findings — audit scope appears clean.\n", fg="green"))


# --------------------------------------------------------------------------- #
# vigil forensics audit report                                                 #
# --------------------------------------------------------------------------- #

@audit_app.command("report")
def audit_report(
    audit_id: str = typer.Option(..., "--audit-id", help="Audit ID from `vigil forensics audit init`."),
    format: str = typer.Option("json", "--format", help="Output format: 'json' or 'pdf'."),
    out: Optional[Path] = typer.Option(None, "--out", help="Output file path (default: audit dir)."),
) -> None:
    """Generate an audit report from a completed scan."""
    audit_dir = Path(".vigil-data/audits") / audit_id
    meta_path = audit_dir / "metadata.json"

    if not meta_path.exists():
        typer.echo(typer.style(f"Error: audit '{audit_id}' not found.", fg="red"), err=True)
        raise typer.Exit(code=2)

    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    scan_results = meta.get("scan_results", {})
    if not scan_results:
        typer.echo(typer.style("Error: audit has not been scanned yet. Run `vigil forensics audit scan` first.", fg="red"), err=True)
        raise typer.Exit(code=2)

    snapshots: list[dict] = []
    for snap_path in scan_results.get("snapshots", []):
        p = Path(snap_path)
        if p.exists():
            try:
                snapshots.append(json.loads(p.read_text(encoding="utf-8")))
            except Exception:
                pass

    report = {
        "vigil_version": "0.1.0",
        "report_type": "forensic_audit",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "audit_id": audit_id,
        "client": meta.get("client"),
        "application": meta.get("application"),
        "created_at": meta.get("created_at"),
        "sources": meta.get("sources", []),
        "turns_scanned": scan_results.get("turns_scanned", 0),
        "findings_count": scan_results.get("findings", 0),
        "findings": snapshots,
        "methodology": {
            "detector": "Vigil deterministic pattern matching (Tier 1–3)",
            "llm_calls": False,
        },
    }

    if format == "json":
        default_out = audit_dir / "report.json"
        output_path = out or default_out
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        typer.echo(typer.style(f"✓ JSON report written to {output_path}", fg="green"))
    elif format == "pdf":
        try:
            from canari_forensics.pdf import SimplePDF  # type: ignore[import]
            default_out = audit_dir / "report.pdf"
            output_path = out or default_out
            pdf = SimplePDF(str(output_path))
            pdf.add_title(f"Vigil Forensic Audit Report: {audit_id}")
            pdf.add_section("Summary")
            pdf.add_text(f"Client: {meta.get('client', 'unknown')}")
            pdf.add_text(f"Application: {meta.get('application', 'unknown')}")
            pdf.add_text(f"Turns scanned: {scan_results.get('turns_scanned', 0)}")
            pdf.add_text(f"Findings: {scan_results.get('findings', 0)}")
            if snapshots:
                pdf.add_section("Findings")
                for snap in snapshots:
                    pdf.add_text(
                        f"[{snap.get('metadata', {}).get('severity', '?')}] "
                        f"{snap.get('canary', {}).get('token_type', '?')} — "
                        f"snapshot {snap.get('metadata', {}).get('snapshot_id', '?')[:8]}…"
                    )
            pdf.save()
            typer.echo(typer.style(f"✓ PDF report written to {output_path}", fg="green"))
        except Exception as exc:
            typer.echo(typer.style(f"Error generating PDF: {exc}", fg="red"), err=True)
            raise typer.Exit(code=2)
    else:
        typer.echo(typer.style(f"Error: unsupported format '{format}'. Use 'json' or 'pdf'.", fg="red"), err=True)
        raise typer.Exit(code=2)


# --------------------------------------------------------------------------- #
# vigil test                                                                   #
# --------------------------------------------------------------------------- #

@app.command()
def test(
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help=(
            "Directory containing .bp.json snapshots (from `vigil forensics scan` or live Canari). "
            "Falls back to paths.attacks in .vigil.yml (default: ./tests/attacks)."
        ),
        show_default=False,
    ),
    prompt: Optional[str] = typer.Option(
        None, "--prompt",
        help="Current system prompt as an inline string.",
        show_default=False,
    ),
    prompt_file: Optional[Path] = typer.Option(
        None, "--prompt-file",
        help="Path to a file containing the current system prompt.",
        show_default=False,
    ),
    report: bool = typer.Option(
        False,
        "--report",
        help="Write a JSON report to ./vigil-report.json.",
    ),
) -> None:
    """Replay every .bp.json attack snapshot against your current system prompt using BreakPoint.

    Exit code 0 = all attacks neutralised.
    Exit code 1 = one or more attacks still succeed (BLOCK).
    Exit code 2 = configuration or runtime error.
    """
    cfg = VigilConfig.load()

    effective_attacks, attacks_from_cfg = _resolve_path(
        attacks_dir, cfg.paths.attacks, Path("./tests/attacks")
    )

    if prompt and prompt_file:
        typer.echo(typer.style("Error: provide --prompt or --prompt-file, not both.", fg="red"), err=True)
        raise typer.Exit(code=2)

    if not prompt and not prompt_file:
        typer.echo(typer.style("Error: one of --prompt or --prompt-file is required.", fg="red"), err=True)
        raise typer.Exit(code=2)

    if prompt_file:
        if not prompt_file.exists():
            typer.echo(typer.style(f"Error: file not found: {prompt_file}", fg="red"), err=True)
            raise typer.Exit(code=2)
        current_system_prompt = prompt_file.read_text(encoding="utf-8").strip()
    else:
        current_system_prompt = (prompt or "").strip()

    if not current_system_prompt:
        typer.echo(typer.style("Error: system prompt is empty.", fg="red"), err=True)
        raise typer.Exit(code=2)

    _echo_sep("Vigil Regression Suite")
    typer.echo(f"  Attacks dir:  {effective_attacks}{_source_label(attacks_from_cfg)}")
    preview = current_system_prompt[:60].replace("\n", " ")
    typer.echo(f"  System prompt: \"{preview}{'...' if len(current_system_prompt) > 60 else ''}\"")
    _echo_sep()

    runner = VigilBreakPointRunner()
    try:
        summary = runner.run_regression_suite(effective_attacks, current_system_prompt)
    except Exception as exc:
        typer.echo(typer.style(f"Error running regression suite: {exc}", fg="red", bold=True), err=True)
        raise typer.Exit(code=2)

    if summary["results"]:
        typer.echo("  Results:")
        for r in summary["results"]:
            codes = f"  {', '.join(r['reason_codes'])}" if r["reason_codes"] else ""
            typer.echo(f"    {_status_color(r['status'])}  {r['file']}{codes}")
    else:
        typer.echo("  No attack snapshots found in the attacks directory.")

    typer.echo("")
    _echo_sep("Summary")

    total   = summary["total"]
    allowed = summary["allowed"]
    warned  = summary["warned"]
    blocked = summary["blocked"]
    errors  = summary["errors"]

    typer.echo(f"  Total snapshots:  {total}")
    typer.echo(f"  {typer.style('ALLOW', fg='green',  bold=True)}  (safe):        {allowed}")
    typer.echo(f"  {typer.style('WARN ', fg='yellow', bold=True)}  (review):      {warned}")
    typer.echo(f"  {typer.style('BLOCK', fg='red',    bold=True)}  (vulnerable):  {blocked}")
    if errors:
        typer.echo(f"  Parse errors:     {errors}")

    _echo_sep()

    if report:
        report_path = _write_test_report(Path("vigil-report.json"), summary)
        typer.echo(f"  JSON report:     {report_path}")
        _echo_sep()

    if blocked > 0:
        typer.echo(
            typer.style(
                f"\n  ✗ {blocked} attack(s) still succeed against the current prompt"
                " — update your defences.\n",
                fg="red", bold=True,
            )
        )
        raise typer.Exit(code=1)
    elif warned > 0:
        typer.echo(
            typer.style(
                f"\n  ⚠ {warned} borderline result(s) — review before deploying.\n",
                fg="yellow",
            )
        )
    else:
        typer.echo(
            typer.style(
                "\n  ✓ All known attacks are neutralised by the current system prompt.\n",
                fg="green", bold=True,
            )
        )


# --------------------------------------------------------------------------- #
# vigil audit (backwards-compat alias for vigil forensics scan)               #
# --------------------------------------------------------------------------- #

@app.command(hidden=True)
def audit(
    logs: Optional[Path] = typer.Option(None, "--logs", show_default=False),
    format: Optional[LogFormat] = typer.Option(None, "--format", show_default=False),
    attacks_dir: Optional[Path] = typer.Option(None, "--attacks-dir", show_default=False),
) -> None:
    """Deprecated alias for `vigil forensics scan`. Use that instead."""
    typer.echo(typer.style("Note: `vigil audit` is deprecated — use `vigil forensics scan`.", fg="yellow"))
    forensics_scan(logs=logs, format=format, attacks_dir=attacks_dir, registry=None, since=None, until=None)


# --------------------------------------------------------------------------- #
# vigil network pull                                                          #
# --------------------------------------------------------------------------- #

@network_app.command("pull")
def network_pull(
    community: bool = typer.Option(
        False,
        "--community",
        help="Pull snapshots from the built-in community attack library.",
        is_flag=True,
    ),
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help="Destination directory for pulled snapshots. Falls back to paths.attacks in .vigil.yml.",
        show_default=False,
    ),
) -> None:
    """Pull attack snapshots from the Vigil network."""
    if not community:
        typer.echo(
            typer.style(
                "Error: choose a source. For now, use `vigil network pull --community`.",
                fg="red",
            ),
            err=True,
        )
        raise typer.Exit(code=2)

    cfg = VigilConfig.load()
    effective_attacks, from_cfg = _resolve_path(attacks_dir, cfg.paths.attacks, Path("./tests/attacks"))

    copied = import_community_attacks(effective_attacks)
    if copied:
        typer.echo(typer.style(f"Downloaded {len(copied)} community snapshot(s).", fg="green"))
        typer.echo(f"  Destination: {effective_attacks}{_source_label(from_cfg)}")
        typer.echo("  Run `vigil test --network` equivalent:")
        typer.echo(f"    vigil test --attacks-dir {effective_attacks} --prompt-file <file>")
    else:
        typer.echo(typer.style("No community snapshots available.", fg="yellow"))


# --------------------------------------------------------------------------- #
# vigil attacks  (sub-app)                                                    #
# --------------------------------------------------------------------------- #

attacks_app = typer.Typer(
    name="attacks",
    help="Manage the community and local attack snapshot library.",
    no_args_is_help=True,
)
app.add_typer(attacks_app, name="attacks")


@attacks_app.command("list")
def attacks_list(
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help="Directory containing .bp.json snapshots. Falls back to paths.attacks in .vigil.yml.",
        show_default=False,
    ),
    source: Optional[str] = typer.Option(None, "--source", help="Filter by source (e.g. canari, forensics, community)."),
    severity: Optional[str] = typer.Option(None, "--severity", help="Filter by severity (low, medium, high, critical)."),
) -> None:
    """List all .bp.json attack snapshots in the attacks directory."""
    cfg = VigilConfig.load()
    effective_attacks, from_cfg = _resolve_path(attacks_dir, cfg.paths.attacks, Path("./tests/attacks"))

    entries = list_attacks(effective_attacks)
    if not entries:
        typer.echo(typer.style(f"No snapshots found in {effective_attacks}.", fg="yellow"))
        return

    if source:
        entries = [e for e in entries if e.get("source", "").lower() == source.lower()]
    if severity:
        entries = [e for e in entries if e.get("severity", "").lower() == severity.lower()]

    _echo_sep("Attack Snapshots")
    typer.echo(f"  Directory: {effective_attacks}{_source_label(from_cfg)}")
    typer.echo(f"  Total: {len(entries)}")
    _echo_sep()

    for entry in entries:
        if "error" in entry:
            typer.echo(f"  {typer.style('ERROR', fg='red')}  {entry['file']} — {entry['error']}")
            continue
        sev = entry.get("severity", "?")
        src = entry.get("source", "?")
        color = {"high": "red", "critical": "red", "medium": "yellow", "low": "green"}.get(sev, "white")
        sev_label = typer.style(f"{sev.upper():<8}", fg=color)
        src_label = typer.style(f"{src:<12}", fg="cyan")
        typer.echo(f"  {sev_label}  {src_label}  {entry['file']}")
        if entry.get("description"):
            typer.echo(f"    {entry['description'][:80]}")


@attacks_app.command("import")
def attacks_import(
    source: Path = typer.Option(..., "--in", help="Source directory containing .bp.json files to import."),
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help="Destination directory. Falls back to paths.attacks in .vigil.yml.",
        show_default=False,
    ),
    source_label: Optional[str] = typer.Option(
        None, "--source",
        help="Override the metadata.source field in imported snapshots (e.g. 'community').",
    ),
) -> None:
    """Import .bp.json attack snapshots from a directory into the attacks library."""
    cfg = VigilConfig.load()
    effective_attacks, from_cfg = _resolve_path(attacks_dir, cfg.paths.attacks, Path("./tests/attacks"))

    if not source.exists() or not source.is_dir():
        typer.echo(typer.style(f"Error: source directory not found: {source}", fg="red"), err=True)
        raise typer.Exit(code=2)

    copied = import_attacks(source, effective_attacks, source_label=source_label)
    if copied:
        typer.echo(typer.style(f"Imported {len(copied)} snapshot(s) to {effective_attacks}", fg="green"))
        for p in copied:
            typer.echo(f"  → {Path(p).name}")
    else:
        typer.echo(typer.style("No .bp.json files found in the source directory.", fg="yellow"))


@attacks_app.command("import-community")
def attacks_import_community(
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help="Destination directory. Falls back to paths.attacks in .vigil.yml.",
        show_default=False,
    ),
) -> None:
    """Import the built-in community attack patterns into the attacks library.

    Ships 6 common attack patterns covering context dump, jailbreak, indirect
    injection, PII extraction, prompt override, and URL exfiltration.
    """
    cfg = VigilConfig.load()
    effective_attacks, from_cfg = _resolve_path(attacks_dir, cfg.paths.attacks, Path("./tests/attacks"))

    copied = import_community_attacks(effective_attacks)
    if copied:
        typer.echo(typer.style(f"Imported {len(copied)} community attack pattern(s) to {effective_attacks}", fg="green"))
        for p in copied:
            typer.echo(f"  → {Path(p).name}")
        typer.echo(f"\n  Run `vigil test --attacks-dir {effective_attacks} --prompt-file <file>` to replay them.")
    else:
        typer.echo(typer.style("No community attacks found (package may be missing the attacks/ directory).", fg="yellow"))


@attacks_app.command("run")
def attacks_run(
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help="Directory containing .bp.json snapshots.",
        show_default=False,
    ),
    prompt: Optional[str] = typer.Option(None, "--prompt", help="Current system prompt as inline string."),
    prompt_file: Optional[Path] = typer.Option(None, "--prompt-file", help="Path to system prompt file."),
    all_attacks: bool = typer.Option(False, "--all", help="Run all snapshots (equivalent to default behaviour).", is_flag=True),
) -> None:
    """Alias for `vigil test`. Replay all attack snapshots against the current system prompt."""
    test(attacks_dir=attacks_dir, prompt=prompt, prompt_file=prompt_file)
