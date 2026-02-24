"""Regression suite: replay stored attack snapshots through BreakPoint."""

from __future__ import annotations

from pathlib import Path
from typing import TypedDict

from breakpoint import evaluate

from vigil.models import AttackSnapshot

_SAFE_REJECTION = "I'm sorry, I can't help with that request."


class AttackResult(TypedDict):
    file: str
    snapshot_id: str
    attack_prompt: str         # malicious user input
    candidate_output: str      # LLM response that was evaluated
    status: str                # "ALLOW" | "WARN" | "BLOCK"
    reason_codes: list[str]


class RegressionSummary(TypedDict):
    total: int
    allowed: int     # status == "ALLOW"  → attack neutralised (safe)
    warned: int      # status == "WARN"   → borderline, review needed
    blocked: int     # status == "BLOCK"  → attack succeeded (vulnerable)
    errors: int      # files that failed to load / parse
    results: list[AttackResult]


class VigilBreakPointRunner:
    """
    Replays saved .bp.json attack snapshots through BreakPoint.

    For each snapshot the runner evaluates the *assistant response* captured
    at the time of the attack (i.e. the LLM output that triggered the canary)
    against a known-safe baseline.

    Decision semantics:
      BLOCK  — the captured LLM response still contains safety violations
               (PII / red-team patterns) → the application was / remains vulnerable.
      ALLOW  — the response is clean → the attack pattern is neutralised.

    BreakPoint is called in "full" mode so that both the PII policy and the
    red-team policy run.  Drift / cost / latency policies are intentionally
    bypassed here because we are doing attack replay, not regression testing.
    """

    def run_regression_suite(
        self,
        attacks_dir: str | Path,
        current_system_prompt: str,
    ) -> RegressionSummary:
        """
        Loop every .bp.json in *attacks_dir*, load it as an AttackSnapshot,
        extract the assistant response (candidate) and baseline, then pass
        them through BreakPoint.

        Returns a summary of ALLOW / WARN / BLOCK verdicts.
        """
        attacks_path = Path(attacks_dir)
        bp_files = sorted(attacks_path.glob("*.bp.json"))

        results: list[AttackResult] = []
        errors = 0

        for bp_file in bp_files:
            try:
                snapshot = AttackSnapshot.load_from_file(bp_file)
            except Exception:
                errors += 1
                continue

            attack_prompt = _extract_user_input(snapshot)
            candidate_output = _extract_assistant_output(snapshot)
            baseline_output = _build_baseline(snapshot, current_system_prompt)

            # Evaluate the captured LLM response (candidate) against the
            # known-safe baseline using BreakPoint's full policy suite.
            # "full" mode activates red_team + pii + output_contract in addition
            # to cost / drift / latency — we get the broadest safety signal.
            decision = evaluate(
                baseline={"output": baseline_output},
                candidate={"output": candidate_output},
                mode="full",
            )

            results.append(
                AttackResult(
                    file=bp_file.name,
                    snapshot_id=snapshot.metadata.snapshot_id,
                    attack_prompt=attack_prompt,
                    candidate_output=candidate_output,
                    status=decision.status,
                    reason_codes=list(decision.reason_codes),
                )
            )

        allowed = sum(1 for r in results if r["status"] == "ALLOW")
        warned  = sum(1 for r in results if r["status"] == "WARN")
        blocked = sum(1 for r in results if r["status"] == "BLOCK")

        return RegressionSummary(
            total=len(bp_files),
            allowed=allowed,
            warned=warned,
            blocked=blocked,
            errors=errors,
            results=results,
        )


# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _extract_user_input(snapshot: AttackSnapshot) -> str:
    """Return the first user-role message; fall back to attack_prompt; else ''."""
    if snapshot.attack.attack_prompt:
        return snapshot.attack.attack_prompt
    for message in snapshot.attack.conversation:
        if message.role == "user":
            return message.content
    return ""


def _extract_assistant_output(snapshot: AttackSnapshot) -> str:
    """
    Return the assistant turn from the snapshot conversation — this is the
    LLM response that triggered the canary and must be evaluated.

    Falls back to the attack_prompt (user input) if no assistant turn exists
    (e.g. snapshots created before this field was populated).
    """
    for message in snapshot.attack.conversation:
        if message.role == "assistant":
            return message.content
    # Legacy fallback: no assistant message stored — use the user input so
    # BreakPoint can still run red_team / PII checks on the attack text itself.
    return _extract_user_input(snapshot)


def _build_baseline(snapshot: AttackSnapshot, current_system_prompt: str) -> str:
    """
    Determine the BreakPoint baseline output.

    Priority:
    1. snapshot.breakpoint_test.baseline.output   — explicit expected safe response
    2. current_system_prompt                       — caller-supplied safe context
    3. Hard-coded safe rejection string            — last resort
    """
    if (
        snapshot.breakpoint_test is not None
        and snapshot.breakpoint_test.baseline is not None
        and snapshot.breakpoint_test.baseline.output
    ):
        return snapshot.breakpoint_test.baseline.output

    if current_system_prompt:
        return current_system_prompt

    return _SAFE_REJECTION
