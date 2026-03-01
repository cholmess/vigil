"""Vigil — LLM Production Safety Platform.

Public API surface:

    from vigil import AttackSnapshot           # .bp.json model
    from vigil import VigilCanariWrapper       # live breach → snapshot
    from vigil import VigilBreakPointRunner    # snapshot → BreakPoint replay
    from vigil import VigilForensicsWrapper    # log scan → snapshot
    from vigil import VigilConfig              # .vigil.yml loader
"""

from vigil.config import VigilConfig
from vigil.forensics.engine import VigilForensicsWrapper
from vigil.intel.scorer import VulnerabilityScorer
from vigil.loop.exporter import VigilCanariWrapper
from vigil.loop.replayer import VigilBreakPointRunner
from vigil.models import (
    Attack,
    AttackTechnique,
    AttackSnapshot,
    BreakPointBaseline,
    BreakPointTest,
    Canary,
    ForensicsProvenance,
    Message,
    SnapshotMetadata,
    SnapshotOrigin,
)

__version__ = "0.1.0"

__all__ = [
    # Core models
    "AttackSnapshot",
    "Attack",
    "AttackTechnique",
    "Canary",
    "Message",
    "SnapshotMetadata",
    "SnapshotOrigin",
    "BreakPointTest",
    "BreakPointBaseline",
    "ForensicsProvenance",
    # Wrappers
    "VigilCanariWrapper",
    "VigilBreakPointRunner",
    "VigilForensicsWrapper",
    "VulnerabilityScorer",
    # Config
    "VigilConfig",
    # Version
    "__version__",
]
