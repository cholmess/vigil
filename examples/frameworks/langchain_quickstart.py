"""LangChain quickstart integration with Vigil."""

from __future__ import annotations

from vigil.canari import CanariClient
from vigil.loop.exporter import VigilCanariWrapper

SYSTEM_PROMPT = "You are a retrieval assistant."


def handle_turn(user_input: str, assistant_output: str) -> None:
    # In real code, assistant_output comes from your LangChain chain.invoke(...)
    canari = CanariClient(db_path="canari.db", stdout=False)
    wrapper = VigilCanariWrapper(canari)
    wrapper.process_turn(
        system_prompt=SYSTEM_PROMPT,
        user_input=user_input,
        llm_output=assistant_output,
        attacks_dir="./tests/attacks",
        application="langchain-app",
    )
