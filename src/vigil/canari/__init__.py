"""Vigil canari engine — internalized Canari runtime IDS."""

from vigil.canari.adapters import RunnableWrapper, patch_openai_client, wrap_runnable
from vigil.canari.alerter import AlertDispatcher
from vigil.canari.client import CanariClient, init
from vigil.canari.detection import DetectionAssessment, ExfiltrationAnalyzer
from vigil.canari.generator import CanaryGenerator
from vigil.canari.incidents import IncidentManager, IncidentSnapshot
from vigil.canari.injector import (
    inject_as_document,
    inject_into_system_prompt,
    wrap_context_assembler,
)
from vigil.canari.integrations import (
    ChainWrapper,
    QueryEngineWrapper,
    inject_canaries_into_index,
    wrap_chain,
    wrap_query_engine,
)
from vigil.canari.models import (
    AlertEvent,
    AlertSeverity,
    CanaryToken,
    InjectionStrategy,
    TokenType,
)
from vigil.canari.registry import CanaryRegistry
from vigil.canari.scanner import OutputScanner

__all__ = [
    "AlertDispatcher",
    "AlertEvent",
    "AlertSeverity",
    "CanariClient",
    "CanaryGenerator",
    "CanaryRegistry",
    "CanaryToken",
    "ChainWrapper",
    "DetectionAssessment",
    "ExfiltrationAnalyzer",
    "IncidentManager",
    "IncidentSnapshot",
    "InjectionStrategy",
    "OutputScanner",
    "QueryEngineWrapper",
    "RunnableWrapper",
    "TokenType",
    "init",
    "inject_as_document",
    "inject_canaries_into_index",
    "inject_into_system_prompt",
    "patch_openai_client",
    "wrap_chain",
    "wrap_context_assembler",
    "wrap_query_engine",
    "wrap_runnable",
]
