"""Anthropic API quickstart integration with Vigil."""

from __future__ import annotations

from vigil.canari import CanariClient
from vigil.loop.exporter import VigilCanariWrapper

SYSTEM_PROMPT = "You are a Claude-style assistant."


def on_claude_response(user_input: str, assistant_output: str, request_id: str) -> None:
    canari = CanariClient(db_path="canari.db", stdout=False)
    wrapper = VigilCanariWrapper(canari)
    wrapper.process_turn(
        system_prompt=SYSTEM_PROMPT,
        user_input=user_input,
        llm_output=assistant_output,
        attacks_dir="./tests/attacks",
        application="anthropic-api",
        context={"request_id": request_id},
    )
