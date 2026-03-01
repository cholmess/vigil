"""OpenAI Assistants-style quickstart integration with Vigil."""

from __future__ import annotations

from vigil.canari import CanariClient
from vigil.loop.exporter import VigilCanariWrapper

SYSTEM_PROMPT = "You are an assistant running in a thread."


def after_assistant_reply(thread_id: str, user_input: str, assistant_output: str) -> None:
    canari = CanariClient(db_path="canari.db", stdout=False)
    wrapper = VigilCanariWrapper(canari)
    wrapper.process_turn(
        system_prompt=SYSTEM_PROMPT,
        user_input=user_input,
        llm_output=assistant_output,
        attacks_dir="./tests/attacks",
        application="assistants-api",
        context={"thread_id": thread_id},
    )
