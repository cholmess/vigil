"""Standalone Act 1 display check (no Typer / no vigil CLI binary required)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sys

try:
    from vigil.forensics.engine import VigilForensicsWrapper
except ModuleNotFoundError:
    repo_src = Path(__file__).resolve().parents[2] / "src"
    sys.path.insert(0, str(repo_src))
    from vigil.forensics.engine import VigilForensicsWrapper


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
        rel = p.relative_to(attacks_dir)
        return f"{attacks_dir.name}/{rel.as_posix()}"
    except ValueError:
        return str(p)


def _display_attacks_dir(attacks_dir: Path) -> str:
    try:
        return attacks_dir.relative_to(Path.cwd()).as_posix().rstrip("/") + "/"
    except ValueError:
        return f"{attacks_dir.name}/"


def main() -> None:
    demo_dir = Path(__file__).resolve().parent
    logs_dir = demo_dir / "sample-logs"
    attacks_dir = demo_dir / "attacks"
    attacks_dir.mkdir(parents=True, exist_ok=True)

    print("════════════════════════════════════════════════")
    print("ACT 1: SCANNING HISTORICAL LOGS")
    print("════════════════════════════════════════════════")
    print("")
    print(f"Scanning logs from: {logs_dir}")
    print("")

    wrapper = VigilForensicsWrapper()
    summary = wrapper.run_audit(logs_dir, format="otel", attacks_dir=attacks_dir)

    print(f"Scanned: {summary['turns_parsed']} turns")
    print("")

    details = summary.get("finding_details", [])
    if details:
        print(f"INCIDENTS FOUND: {summary['findings']}")
        print("")
        for finding in details:
            severity = str(finding.get("severity", "UNKNOWN")).upper()
            pattern_id = str(finding.get("pattern_id", "unknown"))
            ago = _relative_ago(str(finding.get("timestamp", "")))
            snippet = _truncate(str(finding.get("context", "")))
            print(f"{severity} — {pattern_id}")
            print(f"  {ago}")
            if snippet:
                print(f"  Context: \"{snippet}\"")
            print("")

        print("These incidents occurred before you were monitoring.")
        print(f"Exported as BreakPoint snapshots → {_display_attacks_dir(attacks_dir)}")
        for path in summary["saved"]:
            print(f"→ {_format_snapshot_display(path, attacks_dir)}")
    else:
        print("No findings — logs appear clean.")


if __name__ == "__main__":
    main()
