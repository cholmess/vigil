"""Vigil CLI — unified LLM production safety platform commands."""

from __future__ import annotations

import json
import os
import subprocess
import uuid
from collections import Counter
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from vigil.config import VigilConfig
from vigil.forensics.engine import VigilForensicsWrapper
from vigil.intel.scorer import VulnerabilityScorer
from vigil.models import AttackSnapshot
from vigil.loop.library import (
    import_attacks,
    import_community_attacks,
    list_attacks,
)
from vigil.loop.diff_aware import (
    extract_changed_tokens_from_diff,
    infer_relevant_techniques,
    select_snapshots_for_diff,
)
from vigil.loop.heal import hardening_suggestions_for_files
from vigil.loop.heal_intelligent import (
    estimate_shield_score_after_changes,
    rank_suggestions_with_profile,
)
from vigil.loop.replayer import VigilBreakPointRunner
from vigil.loop.swarm import run_swarm_test
from vigil.network.exchange import (
    pull_exchange_snapshots,
    read_network_state,
    read_last_pull_since,
    store_exchange_snapshot,
    write_network_state,
)
from vigil.network.corpus import export_corpus_jsonl
from vigil.network.intel import class_trends, load_manifest_records, technique_trends
from vigil.network.sanitizer import sanitize_snapshot_file

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


def _resolve_diff_base(base_ref: str | None) -> str:
    if base_ref:
        return base_ref
    github_base = os.getenv("GITHUB_BASE_REF")
    if github_base:
        return f"origin/{github_base}"
    return "HEAD~1"


def _prompt_diff_text(prompt_file: Path, base_ref: str | None) -> str:
    base = _resolve_diff_base(base_ref)
    cmd = ["git", "diff", "--unified=0", base, "--", str(prompt_file)]
    try:
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
    except Exception:
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout


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
    diff_aware: bool = typer.Option(
        False,
        "--diff-aware",
        help="Run only snapshots relevant to prompt changes.",
        is_flag=True,
    ),
    base_ref: Optional[str] = typer.Option(
        None,
        "--base-ref",
        help="Git ref to diff against for --diff-aware (default: GITHUB_BASE_REF or HEAD~1).",
        show_default=False,
    ),
    network: bool = typer.Option(
        False,
        "--network",
        help="Run against snapshots pulled from the network cache.",
        is_flag=True,
    ),
) -> None:
    """Replay every .bp.json attack snapshot against your current system prompt using BreakPoint.

    Exit code 0 = all attacks neutralised.
    Exit code 1 = one or more attacks still succeed (BLOCK).
    Exit code 2 = configuration or runtime error.
    """
    cfg = VigilConfig.load()

    if network and attacks_dir is None:
        effective_attacks = Path(".vigil-data/network/pulled")
        attacks_from_cfg = False
    else:
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

    all_snapshot_files = sorted(Path(effective_attacks).glob("*.bp.json"))
    selected_files: list[Path] | None = None

    if diff_aware:
        if prompt_file is None:
            typer.echo(
                typer.style("Error: --diff-aware requires --prompt-file.", fg="red"),
                err=True,
            )
            raise typer.Exit(code=2)
        diff_text = _prompt_diff_text(prompt_file, base_ref)
        changed_tokens = extract_changed_tokens_from_diff(diff_text)
        relevant_techniques = infer_relevant_techniques(changed_tokens)
        selected_files = select_snapshots_for_diff(
            effective_attacks,
            changed_tokens=changed_tokens,
            relevant_techniques=relevant_techniques,
        )
        # Fallback to full suite when diff parsing yields no reliable selection.
        if not selected_files:
            selected_files = all_snapshot_files

    title = "Vigil Regression Suite (diff-aware)" if diff_aware else "Vigil Regression Suite"
    _echo_sep(title)
    typer.echo(f"  Attacks dir:  {effective_attacks}{_source_label(attacks_from_cfg)}")
    preview = current_system_prompt[:60].replace("\n", " ")
    typer.echo(f"  System prompt: \"{preview}{'...' if len(current_system_prompt) > 60 else ''}\"")
    if diff_aware:
        total_available = len(all_snapshot_files)
        total_selected = len(selected_files or [])
        typer.echo(f"  Running {total_selected} of {total_available} attacks relevant to this diff")
    _echo_sep()

    runner = VigilBreakPointRunner()
    try:
        summary = runner.run_regression_suite(
            effective_attacks,
            current_system_prompt,
            snapshot_files=selected_files,
        )
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

    if network:
        shield_pct = round((allowed / total) * 100, 2) if total else 0.0
        net_state = read_network_state()
        last_pull_count = int(net_state.get("last_pull_count", 0) or 0)
        typer.echo(f"  Shield score: {allowed}/{total} ({shield_pct}%)")
        if last_pull_count > 0:
            typer.echo(f"  ↑ {last_pull_count} new attacks tested since last sync")
        if blocked > 0:
            typer.echo(f"  ✗ {blocked} attacks succeed against your current prompt")
            typer.echo("  Run `vigil heal --network --prompt-file <file>` for hardening suggestions")
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
# vigil heal                                                                   #
# --------------------------------------------------------------------------- #

@app.command()
def heal(
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help="Directory containing .bp.json snapshots.",
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
    network: bool = typer.Option(
        False,
        "--network",
        help="Use snapshots from .vigil-data/network/pulled.",
        is_flag=True,
    ),
    intelligent: bool = typer.Option(
        False,
        "--intelligent",
        help="Rank hardening suggestions using vulnerability scorer profile.",
        is_flag=True,
    ),
) -> None:
    """Suggest hardening changes for attacks that still succeed."""
    cfg = VigilConfig.load()
    if network and attacks_dir is None:
        effective_attacks = Path(".vigil-data/network/pulled")
    else:
        effective_attacks, _ = _resolve_path(attacks_dir, cfg.paths.attacks, Path("./tests/attacks"))

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

    runner = VigilBreakPointRunner()
    try:
        summary = runner.run_regression_suite(effective_attacks, current_system_prompt)
    except Exception as exc:
        typer.echo(typer.style(f"Error running heal analysis: {exc}", fg="red"), err=True)
        raise typer.Exit(code=2)

    blocked_files = [r["file"] for r in summary["results"] if r["status"] == "BLOCK"]
    if not blocked_files:
        typer.echo(typer.style("No blocked attacks. Your current prompt already neutralizes known snapshots.", fg="green"))
        return

    suggestions = hardening_suggestions_for_files(effective_attacks, blocked_files)
    if not suggestions:
        typer.echo(typer.style("Blocked attacks found, but no hardening suggestions are present in those snapshots.", fg="yellow"))
        raise typer.Exit(code=1)

    if intelligent:
        scorer = VulnerabilityScorer(effective_attacks)
        profile = scorer.assess(current_system_prompt)
        suggestions = rank_suggestions_with_profile(suggestions, profile)
        before, after = estimate_shield_score_after_changes(
            total=summary["total"],
            allowed=summary["allowed"],
            ranked_suggestions=suggestions,
            scorer_report=profile,
        )

        _echo_sep("Vigil Heal (intelligent)")
        typer.echo(f"  Corpus snapshots: {profile['total_snapshots']}")
        typer.echo("  Vulnerability profile:")
        ordered = sorted(
            profile["techniques"].items(),
            key=lambda kv: float(kv[1]["probability"]),
            reverse=True,
        )[:4]
        for name, info in ordered:
            pct = round(float(info["probability"]) * 100, 1)
            typer.echo(f"    {name}: {info['level']} ({pct}%)")
        typer.echo("")
        typer.echo(f"  Estimated shield score after changes: {round(before*100,1)}% -> {round(after*100,1)}%")
        _echo_sep()
    else:
        _echo_sep("Vigil Heal")
        typer.echo(f"  Blocked attacks: {len(blocked_files)}")
        typer.echo(f"  Suggestions:     {len(suggestions)}")
        _echo_sep()

    for idx, item in enumerate(suggestions, start=1):
        sev = item["severity"].upper()
        typer.echo(f"[{idx}] {item['technique']} / {sev} — {item['file']}")
        typer.echo(f"    {item['suggestion']}")
        typer.echo("")

    raise typer.Exit(code=1)


# --------------------------------------------------------------------------- #
# vigil score                                                                  #
# --------------------------------------------------------------------------- #

@app.command("score")
def score(
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help="Directory containing .bp.json snapshots used as scoring corpus.",
        show_default=False,
    ),
    prompt: Optional[str] = typer.Option(
        None, "--prompt",
        help="System prompt text to assess.",
        show_default=False,
    ),
    prompt_file: Optional[Path] = typer.Option(
        None, "--prompt-file",
        help="Path to a file containing the system prompt to assess.",
        show_default=False,
    ),
    network: bool = typer.Option(
        False,
        "--network",
        help="Use .vigil-data/network/pulled as corpus unless --attacks-dir is provided.",
        is_flag=True,
    ),
) -> None:
    """Assess empirical vulnerability risk by attack technique."""
    cfg = VigilConfig.load()
    if network and attacks_dir is None:
        effective_attacks = Path(".vigil-data/network/pulled")
    else:
        effective_attacks, _ = _resolve_path(attacks_dir, cfg.paths.attacks, Path("./tests/attacks"))

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
        prompt_text = prompt_file.read_text(encoding="utf-8").strip()
    else:
        prompt_text = (prompt or "").strip()
    if not prompt_text:
        typer.echo(typer.style("Error: system prompt is empty.", fg="red"), err=True)
        raise typer.Exit(code=2)

    scorer = VulnerabilityScorer(effective_attacks)
    report = scorer.assess(prompt_text)

    _echo_sep("Vulnerability Scorer")
    typer.echo(f"  Corpus: {report['attacks_dir']}")
    typer.echo(f"  Snapshots: {report['total_snapshots']}")
    _echo_sep()

    techniques = report["techniques"]
    ordered = sorted(techniques.items(), key=lambda kv: kv[1]["probability"], reverse=True)
    for name, info in ordered:
        pct = round(float(info["probability"]) * 100, 1)
        typer.echo(
            f"  {name:<16} {info['level']:<6} ({pct:>5.1f}%)  "
            f"similar={info['similar_matches']}/{info['supporting_snapshots']}"
        )

    typer.echo("")
    typer.echo("Top recommendation:")
    typer.echo(f"  {report['top_technique']}: {report['top_recommendation']}")
    typer.echo("")


# --------------------------------------------------------------------------- #
# vigil swarm-test                                                             #
# --------------------------------------------------------------------------- #

@app.command("swarm-test")
def swarm_test(
    workflow: Path = typer.Option(..., "--workflow", help="Path to workflow definition file (e.g. LangGraph)."),
    framework: str = typer.Option("generic", "--framework", help="Framework label (langgraph, langchain, assistants, generic)."),
    attacks_dir: Optional[Path] = typer.Option(
        None, "--attacks-dir",
        help="Directory containing .bp.json snapshots.",
        show_default=False,
    ),
    out_dir: Optional[Path] = typer.Option(
        None, "--out-dir",
        help="Directory to write swarm-* snapshots (default: attacks dir).",
        show_default=False,
    ),
    prompt: Optional[str] = typer.Option(None, "--prompt", help="Current system prompt as an inline string.", show_default=False),
    prompt_file: Optional[Path] = typer.Option(None, "--prompt-file", help="Path to system prompt file.", show_default=False),
) -> None:
    """Run multi-agent attribution over blocked attacks and save swarm snapshots."""
    cfg = VigilConfig.load()
    effective_attacks, _ = _resolve_path(attacks_dir, cfg.paths.attacks, Path("./tests/attacks"))
    effective_out = out_dir or effective_attacks

    if not workflow.exists():
        typer.echo(typer.style(f"Error: workflow file not found: {workflow}", fg="red"), err=True)
        raise typer.Exit(code=2)
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

    result = run_swarm_test(
        workflow_file=workflow,
        attacks_dir=effective_attacks,
        prompt=current_system_prompt,
        framework=framework,
        out_dir=effective_out,
    )
    findings = result["findings"]

    _echo_sep("Vigil Swarm Test")
    typer.echo(f"  Workflow:   {workflow}")
    typer.echo(f"  Framework:  {framework}")
    typer.echo(f"  Attacks:    {effective_attacks}")
    _echo_sep()

    if not findings:
        typer.echo(typer.style("  No blocked attacks detected for this workflow.", fg="green"))
        return

    for finding in findings:
        src_agent, dst_agent = finding["handoff"]
        typer.echo(f"Agent: {src_agent} -> {dst_agent} handoff")
        typer.echo(
            f"Attack: {finding['technique']} / {str(finding['severity']).upper()} ({finding['snapshot_id']})"
        )
        typer.echo(f"Status: {finding['status']}")
        typer.echo(f"Snapshot saved: {finding['saved_snapshot']}")
        typer.echo("")

    raise typer.Exit(code=1)


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
    since: Optional[str] = typer.Option(
        None,
        "--since",
        help="Pull network snapshots submitted on/after this ISO date (e.g. 2026-01-01).",
        show_default=False,
    ),
    framework: Optional[str] = typer.Option(
        None,
        "--framework",
        help="Filter pulled network snapshots by framework tag (e.g. langchain, langgraph).",
        show_default=False,
    ),
    attack_class: Optional[str] = typer.Option(
        None,
        "--class",
        help="Filter pulled network snapshots by attack class tag (e.g. tool-result-injection).",
        show_default=False,
    ),
    network_dir: Path = typer.Option(
        Path(".vigil-data/network"),
        "--network-dir",
        help="Local exchange storage directory.",
    ),
) -> None:
    """Pull attack snapshots from the Vigil network."""
    cfg = VigilConfig.load()

    if community:
        effective_attacks, from_cfg = _resolve_path(attacks_dir, cfg.paths.attacks, Path("./tests/attacks"))
        copied = import_community_attacks(effective_attacks)
        if copied:
            typer.echo(typer.style(f"Downloaded {len(copied)} community snapshot(s).", fg="green"))
            typer.echo(f"  Destination: {effective_attacks}{_source_label(from_cfg)}")
            typer.echo("  Run `vigil test --network` equivalent:")
            typer.echo(f"    vigil test --attacks-dir {effective_attacks} --prompt-file <file>")
        else:
            typer.echo(typer.style("No community snapshots available.", fg="yellow"))
        return

    pulled_dir = attacks_dir or Path(".vigil-data/network/pulled")
    effective_since = since or read_last_pull_since(network_dir=network_dir)
    pulled = pull_exchange_snapshots(
        network_dir=network_dir,
        out_dir=pulled_dir,
        since=effective_since,
        framework=framework,
        attack_class=attack_class,
    )
    if pulled:
        typer.echo(typer.style(f"Downloaded {len(pulled)} network snapshot(s).", fg="green"))
        typer.echo(f"  Destination: {pulled_dir}")
        if effective_since:
            typer.echo(f"  Since: {effective_since}")
        if framework:
            typer.echo(f"  Framework filter: {framework}")
        if attack_class:
            typer.echo(f"  Class filter: {attack_class}")
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        write_network_state(
            network_dir=network_dir,
            updates={
                "last_pull_since": now_iso,
                "last_pull_count": len(pulled),
                "last_pull_at": now_iso,
            },
        )
        typer.echo("  Run:")
        typer.echo("    vigil test --network --prompt-file <file>")
    else:
        typer.echo(typer.style("No matching network snapshots found.", fg="yellow"))


@network_app.command("sanitize")
def network_sanitize(
    source: Path = typer.Option(..., "--in", help="Snapshot file or directory to sanitize."),
    out: Path = typer.Option(
        Path(".vigil-data/network/sanitized"),
        "--out",
        help="Output directory for sanitized snapshots.",
    ),
    term: list[str] = typer.Option(
        [],
        "--term",
        help="Company-specific term to redact (repeat for multiple).",
    ),
) -> None:
    """Sanitize snapshots for safe cross-organization sharing."""
    targets: list[Path]
    if source.is_file():
        targets = [source]
    elif source.is_dir():
        targets = sorted(source.glob("*.bp.json"))
    else:
        typer.echo(typer.style(f"Error: input not found: {source}", fg="red"), err=True)
        raise typer.Exit(code=2)

    if not targets:
        typer.echo(typer.style("No .bp.json snapshots found to sanitize.", fg="yellow"))
        return

    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for item in targets:
        written.append(sanitize_snapshot_file(item, out_dir=out, terms=term))

    typer.echo(typer.style(f"Sanitized {len(written)} snapshot(s).", fg="green"))
    typer.echo(f"  Output: {out}")
    for path in written:
        typer.echo(f"  → {path.name}")


@network_app.command("push")
def network_push(
    snapshot: Path = typer.Argument(..., help="Snapshot .bp.json file to submit."),
    sanitize: bool = typer.Option(
        True,
        "--sanitize/--no-sanitize",
        help="Sanitize snapshot before pushing.",
    ),
    term: list[str] = typer.Option(
        [],
        "--term",
        help="Company-specific term to redact during sanitization.",
    ),
    framework: Optional[str] = typer.Option(
        None,
        "--framework",
        help="Attach a framework tag (e.g. langchain, langgraph, assistants, anthropic).",
        show_default=False,
    ),
    attack_class: Optional[str] = typer.Option(
        None,
        "--attack-class",
        help="Attach attack class tag (e.g. tool-result-injection).",
        show_default=False,
    ),
    network_dir: Path = typer.Option(
        Path(".vigil-data/network"),
        "--network-dir",
        help="Local exchange storage directory.",
    ),
) -> None:
    """Submit a snapshot to the local Vigil exchange store."""
    if not snapshot.exists():
        typer.echo(typer.style(f"Error: snapshot file not found: {snapshot}", fg="red"), err=True)
        raise typer.Exit(code=2)

    candidate = snapshot
    if sanitize:
        staging = network_dir / "staging"
        candidate = sanitize_snapshot_file(snapshot, out_dir=staging, terms=term)

    if framework:
        snap = AttackSnapshot.load_from_file(candidate)
        tags = list(snap.metadata.tags)
        framework_tag = f"framework:{framework.lower()}"
        if framework_tag not in {str(t).lower() for t in tags}:
            tags.append(framework_tag)
            snap = snap.model_copy(update={"metadata": snap.metadata.model_copy(update={"tags": tags})})
            candidate = snap.save_to_file(candidate)
    if attack_class:
        snap = AttackSnapshot.load_from_file(candidate)
        tags = list(snap.metadata.tags)
        class_tag = f"class:{attack_class.lower()}"
        if class_tag not in {str(t).lower() for t in tags}:
            tags.append(class_tag)
            snap = snap.model_copy(update={"metadata": snap.metadata.model_copy(update={"tags": tags})})
            candidate = snap.save_to_file(candidate)

    network_id, stored = store_exchange_snapshot(candidate, network_dir=network_dir)
    typer.echo(typer.style(f"Submitted snapshot. Network ID: {network_id}", fg="green"))
    typer.echo(f"  Stored at: {stored}")


@network_app.command("intel")
def network_intel(
    days: int = typer.Option(7, "--days", help="Comparison window in days."),
    prompt: Optional[str] = typer.Option(
        None,
        "--prompt",
        help="Optional system prompt to compute shield score against top trending class.",
        show_default=False,
    ),
    prompt_file: Optional[Path] = typer.Option(
        None,
        "--prompt-file",
        help="Path to a system prompt file for shield score against top trending class.",
        show_default=False,
    ),
    attacks_dir: Path = typer.Option(
        Path(".vigil-data/network/pulled"),
        "--attacks-dir",
        help="Pulled network snapshot directory used for class shield-score check.",
    ),
    network_dir: Path = typer.Option(
        Path(".vigil-data/network"),
        "--network-dir",
        help="Local exchange storage directory.",
    ),
) -> None:
    """Show trending attack techniques from local exchange history."""
    if days <= 0:
        typer.echo(typer.style("Error: --days must be > 0.", fg="red"), err=True)
        raise typer.Exit(code=2)

    records = load_manifest_records(network_dir=network_dir)
    if not records:
        typer.echo(typer.style("No exchange records available yet.", fg="yellow"))
        return

    trends = technique_trends(records, days=days)
    if not trends:
        typer.echo(typer.style("No trend data available for the selected period.", fg="yellow"))
        return

    _echo_sep("Vigil Threat Intel")
    typer.echo(f"  Window: last {days} days vs previous {days} days")
    typer.echo(f"  Records: {len(records)}")
    _echo_sep()

    top = [row for row in trends if row["current"] > 0][:5]
    if not top:
        typer.echo("  No current-period activity.")
        return

    class_rows = [row for row in class_trends(records, days=days) if row["current"] > 0]
    if class_rows:
        typer.echo("")
        typer.echo("Trending classes:")
        for row in class_rows[:3]:
            arrow = "↑" if row["delta"] > 0 else ("↓" if row["delta"] < 0 else "→")
            typer.echo(
                f"  {row['attack_class']:<24} current={row['current']:<3} "
                f"prev={row['previous']:<3} delta={arrow}{abs(row['delta'])}"
            )

    top_class = class_rows[0]["attack_class"] if class_rows else None

    for row in top:
        arrow = "↑" if row["delta"] > 0 else ("↓" if row["delta"] < 0 else "→")
        typer.echo(
            f"  {row['technique']:<16} current={row['current']:<3} "
            f"prev={row['previous']:<3} delta={arrow}{abs(row['delta'])}"
        )

    if prompt or prompt_file:
        if prompt and prompt_file:
            typer.echo(typer.style("Error: provide --prompt or --prompt-file, not both.", fg="red"), err=True)
            raise typer.Exit(code=2)
        if prompt_file:
            if not prompt_file.exists():
                typer.echo(typer.style(f"Error: file not found: {prompt_file}", fg="red"), err=True)
                raise typer.Exit(code=2)
            prompt_text = prompt_file.read_text(encoding="utf-8").strip()
        else:
            prompt_text = (prompt or "").strip()
        if not prompt_text:
            typer.echo(typer.style("Error: system prompt is empty.", fg="red"), err=True)
            raise typer.Exit(code=2)

        if not top_class:
            typer.echo("\nNo class trend available to score against.")
            return

        class_files: list[Path] = []
        for bp in sorted(Path(attacks_dir).glob("*.bp.json")):
            try:
                snap = AttackSnapshot.load_from_file(bp)
            except Exception:
                continue
            tags = {str(t).lower() for t in snap.metadata.tags}
            if f"class:{top_class}" in tags:
                class_files.append(bp)

        if not class_files:
            typer.echo(f"\nNo pulled snapshots found for class '{top_class}' in {attacks_dir}.")
            typer.echo(f"Run: vigil network pull --class {top_class}")
            return

        runner = VigilBreakPointRunner()
        summary = runner.run_regression_suite(attacks_dir, prompt_text, snapshot_files=class_files)
        total = int(summary["total"])
        allowed = int(summary["allowed"])
        blocked = int(summary["blocked"])
        pct = round((allowed / total) * 100, 2) if total else 0.0

        typer.echo("")
        typer.echo(f"Your shield score against class '{top_class}': {allowed}/{total} ({pct}%)")
        if blocked > 0:
            typer.echo(f"  {blocked} attacks still succeed.")
            typer.echo("  Run:")
            typer.echo(f"    vigil network pull --class {top_class}")
            typer.echo("    vigil test --network --prompt-file <file>")
            typer.echo("    vigil heal --intelligent --network --prompt-file <file>")


@network_app.command("export-corpus")
def network_export_corpus(
    out: Path = typer.Option(
        Path(".vigil-data/network/corpus/corpus.jsonl"),
        "--out",
        help="Output JSONL file path.",
    ),
    since: Optional[str] = typer.Option(
        None,
        "--since",
        help="Export only snapshots submitted on/after this date.",
        show_default=False,
    ),
    framework: Optional[str] = typer.Option(
        None,
        "--framework",
        help="Filter exported rows by framework tag.",
        show_default=False,
    ),
    attack_class: Optional[str] = typer.Option(
        None,
        "--class",
        help="Filter exported rows by attack class tag.",
        show_default=False,
    ),
    network_dir: Path = typer.Option(
        Path(".vigil-data/network"),
        "--network-dir",
        help="Local exchange storage directory.",
    ),
) -> None:
    """Export local exchange snapshots as training-ready JSONL corpus."""
    out_path, rows = export_corpus_jsonl(
        network_dir=network_dir,
        out_file=out,
        since=since,
        framework=framework,
        attack_class=attack_class,
    )
    if rows == 0:
        typer.echo(typer.style("No rows exported (no matching snapshots).", fg="yellow"))
        return
    typer.echo(typer.style(f"Exported corpus rows: {rows}", fg="green"))
    typer.echo(f"  File: {out_path}")


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
