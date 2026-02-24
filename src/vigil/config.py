"""Vigil configuration — loads .vigil.yml from the current working directory."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

_CONFIG_FILENAME = ".vigil.yml"


# --------------------------------------------------------------------------- #
# Config sub-models                                                            #
# --------------------------------------------------------------------------- #

class PathsConfig(BaseModel):
    """File-system paths used across Vigil commands."""

    attacks: Path = Field(
        default=Path("./tests/attacks"),
        description="Directory where .bp.json attack snapshots are stored.",
    )


class CanariConfig(BaseModel):
    """Settings for the live Canari production scanner."""

    tokens: list[str] = Field(
        default_factory=list,
        description="Canary token values injected into production prompts.",
    )
    db_path: str = Field(
        default="canari.db",
        description="Path to the Canari SQLite database.",
    )


class ForensicsConfig(BaseModel):
    """Settings for the canari-forensics historical log scanner."""

    log_dir: Path | None = Field(
        default=None,
        description="Default directory (or file) to scan when --logs is not passed to `vigil audit`.",
    )
    format: str = Field(
        default="otel",
        description="Default log format: 'otel' (OTLP JSON / exported MLflow) or 'mlflow' (MLflow Gateway).",
    )


# --------------------------------------------------------------------------- #
# Root config model                                                            #
# --------------------------------------------------------------------------- #

class VigilConfig(BaseModel):
    """Root configuration model, corresponding to a .vigil.yml file."""

    paths: PathsConfig = Field(default_factory=PathsConfig)
    canari: CanariConfig = Field(default_factory=CanariConfig)
    forensics: ForensicsConfig = Field(default_factory=ForensicsConfig)

    @classmethod
    def load(cls, config_path: str | Path | None = None) -> "VigilConfig":
        """
        Load config from *config_path*, or fall back to .vigil.yml in the
        current working directory. Silently returns all defaults if the file
        is absent — Vigil is fully usable without a config file.
        """
        path = Path(config_path) if config_path else Path.cwd() / _CONFIG_FILENAME

        if not path.exists():
            return cls()

        try:
            import yaml  # PyYAML — declared in pyproject.toml dependencies
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "PyYAML is required to read .vigil.yml. "
                "Install it with: pip install pyyaml"
            ) from exc

        raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return cls.model_validate(raw)
