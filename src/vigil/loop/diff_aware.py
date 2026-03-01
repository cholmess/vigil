"""Diff-aware snapshot selection helpers."""

from __future__ import annotations

import json
import re
from pathlib import Path

from vigil.models import AttackSnapshot

_TOKEN_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_]{2,}")

_TECHNIQUE_HINTS: dict[str, set[str]] = {
    "direct_injection": {
        "inject",
        "instruction",
        "override",
        "prompt",
        "user_input",
    },
    "indirect_rag": {
        "retrieval",
        "retrieved",
        "rag",
        "document",
        "source",
        "context_window",
    },
    "multi_turn": {
        "conversation",
        "history",
        "memory",
        "followup",
        "turn",
    },
    "prompt_leakage": {
        "system_prompt",
        "prompt",
        "secret",
        "leak",
        "never_reveal",
        "instructions",
    },
    "jailbreak": {
        "jailbreak",
        "persona",
        "dan",
        "policy",
        "ignore",
        "unsafe",
    },
    "agent_hijacking": {
        "agent",
        "handoff",
        "orchestrator",
        "delegate",
        "planner",
    },
    "tool_injection": {
        "tool",
        "function",
        "plugin",
        "url",
        "http",
        "api",
    },
}

_TAG_TO_TECHNIQUE = {
    "prompt_injection": "direct_injection",
    "indirect_injection": "indirect_rag",
    "rag_attack": "indirect_rag",
    "system_prompt_override": "jailbreak",
    "url_injection": "tool_injection",
    "roleplay": "jailbreak",
}


def extract_changed_tokens_from_diff(diff_text: str) -> set[str]:
    """Extract lowercase identifier-like tokens from changed diff lines."""
    changed_lines: list[str] = []
    for line in (diff_text or "").splitlines():
        if line.startswith(("+++", "---", "@@")):
            continue
        if line.startswith("+") or line.startswith("-"):
            changed_lines.append(line[1:])
    tokens = set()
    for line in changed_lines:
        for token in _TOKEN_RE.findall(line.lower()):
            tokens.add(token)
    return tokens


def infer_relevant_techniques(changed_tokens: set[str]) -> set[str]:
    """Map changed prompt tokens to likely impacted attack techniques."""
    if not changed_tokens:
        return set()
    relevant: set[str] = set()
    for technique, hints in _TECHNIQUE_HINTS.items():
        if changed_tokens & hints:
            relevant.add(technique)
    return relevant


def select_snapshots_for_diff(
    attacks_dir: str | Path,
    *,
    changed_tokens: set[str],
    relevant_techniques: set[str],
) -> list[Path]:
    """
    Select snapshots likely impacted by this prompt diff.

    Priority:
    - explicit metadata.technique
    - technique inferred from metadata.tags
    - block condition token overlap with changed tokens
    """
    attacks_path = Path(attacks_dir)
    selected: list[Path] = []
    for bp_file in sorted(attacks_path.glob("*.bp.json")):
        try:
            snapshot = AttackSnapshot.load_from_file(bp_file)
        except Exception:
            continue

        meta_technique = snapshot.metadata.technique.value
        tags = {str(t).lower() for t in snapshot.metadata.tags}
        tag_techniques = {_TAG_TO_TECHNIQUE[t] for t in tags if t in _TAG_TO_TECHNIQUE}
        block_conditions = set()
        if snapshot.breakpoint_test is not None:
            for cond in snapshot.breakpoint_test.block_conditions:
                block_conditions.update(_TOKEN_RE.findall(str(cond).lower()))

        if meta_technique in relevant_techniques:
            selected.append(bp_file)
            continue
        if tag_techniques & relevant_techniques:
            selected.append(bp_file)
            continue
        if changed_tokens and (block_conditions & changed_tokens):
            selected.append(bp_file)
            continue

    return selected


def load_snapshot_technique(path: str | Path) -> str:
    """Best-effort read of snapshot technique for display/reporting."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return str((data.get("metadata") or {}).get("technique", "unknown"))
