"""Snapshot sanitization for safe network sharing."""

from __future__ import annotations

import re
from pathlib import Path

from vigil.models import Attack, AttackSnapshot, Message

_STRIPE_KEY_RE = re.compile(r"\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b")
_AWS_ACCESS_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_EMAIL_RE = re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOST_RE = re.compile(r"\b(?:[a-zA-Z0-9\-]+\.)+(?:internal|corp|local|lan|com|net|org|io)\b")


def _redact_sensitive(text: str, terms: list[str] | None = None) -> str:
    out = text or ""
    out = _STRIPE_KEY_RE.sub("sk_live_SYNTHETICXXXXXXXXXXXXXXXX", out)
    out = _AWS_ACCESS_RE.sub("AKIASYNTHETICKEY0000", out)
    out = _EMAIL_RE.sub("redacted_user@redacted.invalid", out)
    out = _IPV4_RE.sub("[REDACTED_IP]", out)
    out = _HOST_RE.sub("[REDACTED_HOST]", out)
    for term in terms or []:
        t = (term or "").strip()
        if not t:
            continue
        out = re.sub(re.escape(t), "[REDACTED_TERM]", out, flags=re.IGNORECASE)
    return out


def _sanitize_message(msg: Message, terms: list[str] | None) -> Message:
    if msg.role == "system":
        skeleton = (
            "[SYSTEM_PROMPT_REDACTED]\n"
            f"length={len(msg.content or '')} chars\n"
            "purpose=preserved_for_attack_structure"
        )
        return Message(role=msg.role, content=skeleton)
    return Message(role=msg.role, content=_redact_sensitive(msg.content, terms))


def sanitize_snapshot(snapshot: AttackSnapshot, *, terms: list[str] | None = None) -> AttackSnapshot:
    """Return a sanitized clone preserving attack structure and labels."""
    sanitized_conv = [_sanitize_message(m, terms) for m in snapshot.attack.conversation]

    tags = list(snapshot.metadata.tags)
    if "sanitized" not in [str(t).lower() for t in tags]:
        tags.append("sanitized")

    sanitized_attack = Attack(
        conversation=sanitized_conv,
        attack_turn_index=snapshot.attack.attack_turn_index,
        attack_prompt=_redact_sensitive(snapshot.attack.attack_prompt or "", terms) or None,
        attack_pattern=snapshot.attack.attack_pattern,
        extracted_value_redacted=snapshot.attack.extracted_value_redacted,
    )

    return AttackSnapshot(
        vigil_version=snapshot.vigil_version,
        snapshot_version=snapshot.snapshot_version,
        snapshot_type=snapshot.snapshot_type,
        metadata=snapshot.metadata.model_copy(update={"tags": tags}),
        origin=snapshot.origin,
        canary=snapshot.canary,
        attack=sanitized_attack,
        breakpoint_test=snapshot.breakpoint_test.model_copy(
            update={
                "hardening_suggestion": _redact_sensitive(
                    snapshot.breakpoint_test.hardening_suggestion or "",
                    terms,
                )
                or None
            }
        )
        if snapshot.breakpoint_test is not None
        else None,
        forensics=snapshot.forensics,
    )


def sanitize_snapshot_file(
    snapshot_file: str | Path,
    *,
    out_dir: str | Path,
    terms: list[str] | None = None,
) -> Path:
    """Load, sanitize, and persist a snapshot to the output directory."""
    source = Path(snapshot_file)
    snapshot = AttackSnapshot.load_from_file(source)
    sanitized = sanitize_snapshot(snapshot, terms=terms)
    name = source.name
    if not name.endswith(".bp.json"):
        name = f"{source.stem}.bp.json"
    dest = Path(out_dir) / name
    return sanitized.save_to_file(dest)
