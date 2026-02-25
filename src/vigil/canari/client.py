"""CanariClient — the main entry point for the Vigil detection engine."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from vigil.canari.adapters import patch_openai_client, wrap_runnable
from vigil.canari.alerter import AlertDispatcher
from vigil.canari.generator import CanaryGenerator
from vigil.canari.incidents import IncidentManager
from vigil.canari.integrations import wrap_chain, wrap_query_engine
from vigil.canari.models import AlertEvent, InjectionStrategy, TokenType
from vigil.canari.registry import CanaryRegistry
from vigil.canari.scanner import OutputScanner


class CanariClient:
    """
    Runtime LLM intrusion detection using honeypot canary tokens.

    Usage::

        honey = CanariClient(db_path="vigil.db")
        honey.generate(TokenType.STRIPE_KEY, injection_location="system_context")
        honey.add_stdout()

        # In your LLM call handler:
        honey.scan_output(llm_response, context={"conversation_id": conv_id})
    """

    def __init__(
        self,
        db_path: str = "vigil.db",
        *,
        stdout: bool = True,
        window_seconds: int = 600,
    ) -> None:
        self.registry = CanaryRegistry(db_path=db_path)
        self._generator = CanaryGenerator()
        self._scanner = OutputScanner(registry=self.registry)
        self._dispatcher = AlertDispatcher()
        self._incidents = IncidentManager(window_seconds=window_seconds)
        self._on_alert_callbacks: list[Callable[[AlertEvent], None]] = []

        if stdout:
            self._dispatcher.add_stdout()

    # ------------------------------------------------------------------
    # Token management
    # ------------------------------------------------------------------

    def generate(
        self,
        token_type: TokenType | None = None,
        *,
        injection_strategy: InjectionStrategy = InjectionStrategy.CONTEXT_APPENDIX,
        injection_location: str = "unassigned",
        metadata: dict | None = None,
        tenant_id: str | None = None,
        application_id: str | None = None,
        # Legacy compatibility kwargs accepted by old canari-llm API
        n_tokens: int | None = None,
        token_types: list[str] | None = None,
    ):
        """Generate one or more canary tokens.

        Accepts both the new positional API (generate(TokenType.X)) and the
        legacy keyword API (generate(n_tokens=2, token_types=["stripe_key"])).
        """
        if token_types is not None or n_tokens is not None:
            # Legacy path: return a list of tokens
            _types = token_types or ["api_key"]
            resolved = [TokenType(_t) for _t in _types]
            count = n_tokens if n_tokens is not None else len(resolved)
            result = []
            for i in range(count):
                tt = resolved[i % len(resolved)]
                token = self._generator.generate(
                    tt,
                    injection_strategy=injection_strategy,
                    injection_location=injection_location,
                    metadata=metadata,
                    tenant_id=tenant_id,
                    application_id=application_id,
                )
                self.registry.add(token)
                result.append(token)
            return result

        if token_type is None:
            raise ValueError("token_type is required when not using legacy keyword API")
        token = self._generator.generate(
            token_type,
            injection_strategy=injection_strategy,
            injection_location=injection_location,
            metadata=metadata,
            tenant_id=tenant_id,
            application_id=application_id,
        )
        self.registry.add(token)
        return token

    def generate_many(self, token_types: list[TokenType], **kwargs):
        return [self.generate(tt, **kwargs) for tt in token_types]

    # ------------------------------------------------------------------
    # Alert dispatch configuration
    # ------------------------------------------------------------------

    def add_webhook(self, url: str, **kwargs) -> None:
        self._dispatcher.add_webhook(url, **kwargs)

    def add_slack(self, webhook_url: str, **kwargs) -> None:
        self._dispatcher.add_slack(webhook_url, **kwargs)

    def add_stdout(self, format: str = "rich") -> None:  # noqa: A002
        self._dispatcher.add_stdout(format=format)

    def add_file(self, path: str) -> None:
        self._dispatcher.add_file(path)

    def add_callback(self, fn: Callable[[AlertEvent], None]) -> None:
        self._dispatcher.add_callback(fn)
        self._on_alert_callbacks.append(fn)

    # ------------------------------------------------------------------
    # Scanning
    # ------------------------------------------------------------------

    def scan_output(self, output: str, context: dict | None = None) -> list[AlertEvent]:
        events = self._scanner.scan(output, context=context)
        for event in events:
            correlated = self._incidents.correlate(event)
            self.registry.record_alert(correlated)
            self._dispatcher.dispatch(correlated)
        return events

    async def scan_output_async(self, output: str, context: dict | None = None) -> list[AlertEvent]:
        events = await self._scanner.scan_async(output, context=context)
        for event in events:
            correlated = self._incidents.correlate(event)
            self.registry.record_alert(correlated)
            self._dispatcher.dispatch(correlated)
        return events

    def wrap_llm_call(self, llm_fn: Callable) -> Callable:
        return self._scanner.wrap_llm_call(llm_fn)

    # ------------------------------------------------------------------
    # Framework wrappers
    # ------------------------------------------------------------------

    def wrap_chain(self, chain: Any):
        return wrap_chain(chain, self.scan_output)

    def wrap_query_engine(self, query_engine: Any):
        return wrap_query_engine(query_engine, self.scan_output)

    def wrap_runnable(self, runnable: Any):
        return wrap_runnable(runnable, self.scan_output)

    def patch_openai_client(self, client: Any) -> dict[str, int]:
        return patch_openai_client(client, self.wrap_llm_call)

    # ------------------------------------------------------------------
    # Registry / history
    # ------------------------------------------------------------------

    def alert_history(self, **kwargs) -> list[AlertEvent]:
        return self.registry.list_alerts(**kwargs)

    def incident_report(self, limit: int = 50):
        return self._incidents.recent_incidents(limit=limit)

    def token_stats(self) -> dict:
        return self.registry.stats()

    def alerter_health(self) -> dict:
        return self._dispatcher.health()

    def doctor(self) -> dict:
        return self.registry.doctor()


def init(
    db_path: str = "vigil.db",
    *,
    stdout: bool = True,
    window_seconds: int = 600,
) -> CanariClient:
    """Factory function — mirrors the canari.init() API."""
    return CanariClient(db_path=db_path, stdout=stdout, window_seconds=window_seconds)
