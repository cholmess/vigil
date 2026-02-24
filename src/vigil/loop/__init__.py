"""vigil.loop — the feedback loop between Canari, Forensics, and BreakPoint.

    from vigil.loop import VigilCanariWrapper     # live breach → .bp.json
    from vigil.loop import VigilBreakPointRunner  # .bp.json → BreakPoint replay
    from vigil.loop import import_community_attacks  # ship community patterns
"""

from vigil.loop.exporter import VigilCanariWrapper
from vigil.loop.library import (
    community_attacks_dir,
    import_attacks,
    import_community_attacks,
    list_attacks,
)
from vigil.loop.replayer import VigilBreakPointRunner

__all__ = [
    "VigilCanariWrapper",
    "VigilBreakPointRunner",
    "community_attacks_dir",
    "import_attacks",
    "import_community_attacks",
    "list_attacks",
]
