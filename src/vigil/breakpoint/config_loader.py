"""Configuration loader for the evaluation engine."""

from __future__ import annotations

import json
import os
from importlib import resources

from vigil.breakpoint.errors import ConfigValidationError
from vigil.breakpoint.waivers import parse_waivers


def load_config(
    config_path: str | None = None,
    environment: str | None = None,
    preset: str | None = None,
) -> dict:
    try:
        default_config = _load_default_config()
        merged_config = default_config

        chosen_path = config_path or os.getenv("VIGIL_EVAL_CONFIG")
        if chosen_path:
            with open(chosen_path, "r", encoding="utf-8") as f:
                custom = json.load(f)
            merged_config = _deep_merge(merged_config, custom)

        chosen_environment = environment or os.getenv("VIGIL_ENV")
        if chosen_environment:
            merged_config = _apply_environment_overrides(merged_config, chosen_environment)
        else:
            merged_config = dict(merged_config)
            merged_config.pop("environments", None)

        _validate_config(merged_config)
        return merged_config
    except ConfigValidationError:
        raise
    except Exception as exc:
        raise ConfigValidationError(str(exc)) from exc


def _load_default_config() -> dict:
    package = "vigil.breakpoint.config"
    resource = resources.files(package).joinpath("default_policies.json")
    with resource.open("r", encoding="utf-8") as f:
        return json.load(f)


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _apply_environment_overrides(config: dict, environment: str) -> dict:
    env_map = config.get("environments")
    if env_map is None:
        raise ConfigValidationError(
            f"Config environment '{environment}' was requested, but no 'environments' section exists."
        )
    if not isinstance(env_map, dict):
        raise ConfigValidationError("Config key 'environments' must be a JSON object.")
    if environment not in env_map:
        available = ", ".join(sorted(env_map.keys())) or "(none)"
        raise ConfigValidationError(
            f"Unknown config environment '{environment}'. Available environments: {available}."
        )
    env_override = env_map.get(environment)
    if not isinstance(env_override, dict):
        raise ConfigValidationError(f"Environment override for '{environment}' must be a JSON object.")
    merged = _deep_merge(config, env_override)
    merged.pop("environments", None)
    return merged


def _validate_config(config: dict) -> None:
    _validate_policy_thresholds(config, policy="cost_policy")
    _validate_policy_thresholds(config, policy="latency_policy")
    _validate_drift_thresholds(config)
    _validate_output_contract_policy(config)
    _validate_red_team_policy(config)
    _validate_strict_mode(config)
    parse_waivers(config.get("waivers"))


def _validate_policy_thresholds(config: dict, policy: str) -> None:
    policy_config = config.get(policy, {})
    if not isinstance(policy_config, dict):
        raise ConfigValidationError(f"Config key '{policy}' must be a JSON object.")
    warn_value = policy_config.get("warn_increase_pct")
    block_value = policy_config.get("block_increase_pct")
    if not isinstance(warn_value, (int, float)):
        raise ConfigValidationError(f"Config key '{policy}.warn_increase_pct' must be numeric.")
    if not isinstance(block_value, (int, float)):
        raise ConfigValidationError(f"Config key '{policy}.block_increase_pct' must be numeric.")
    if float(warn_value) < 0 or float(block_value) < 0:
        raise ConfigValidationError(f"Config key '{policy}' thresholds must be >= 0.")
    if float(block_value) < float(warn_value):
        raise ConfigValidationError(
            f"Config key '{policy}.block_increase_pct' must be >= '{policy}.warn_increase_pct'."
        )


def _validate_drift_thresholds(config: dict) -> None:
    drift = config.get("drift_policy", {})
    if not isinstance(drift, dict):
        raise ConfigValidationError("Config key 'drift_policy' must be a JSON object.")
    for key in ("warn_expansion_pct", "block_expansion_pct", "warn_compression_pct",
                "block_compression_pct", "warn_short_ratio", "warn_min_similarity"):
        value = drift.get(key)
        if not isinstance(value, (int, float)):
            raise ConfigValidationError(f"Config key 'drift_policy.{key}' must be numeric.")


def _validate_output_contract_policy(config: dict) -> None:
    policy = config.get("output_contract_policy", {})
    if not isinstance(policy, dict):
        raise ConfigValidationError("Config key 'output_contract_policy' must be a JSON object.")
    for key in ("enabled", "block_on_invalid_json", "warn_on_missing_keys", "warn_on_type_mismatch"):
        value = policy.get(key)
        if not isinstance(value, bool):
            raise ConfigValidationError(f"Config key 'output_contract_policy.{key}' must be boolean.")


def _validate_red_team_policy(config: dict) -> None:
    policy = config.get("red_team_policy", {})
    if not isinstance(policy, dict):
        raise ConfigValidationError("Config key 'red_team_policy' must be a JSON object.")
    enabled = policy.get("enabled", True)
    if not isinstance(enabled, bool):
        raise ConfigValidationError("Config key 'red_team_policy.enabled' must be boolean.")
    categories = policy.get("categories", {})
    if not isinstance(categories, dict):
        raise ConfigValidationError("Config key 'red_team_policy.categories' must be a JSON object.")


def _validate_strict_mode(config: dict) -> None:
    policy = config.get("strict_mode", {})
    if not isinstance(policy, dict):
        raise ConfigValidationError("Config key 'strict_mode' must be a JSON object.")
    enabled = policy.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ConfigValidationError("Config key 'strict_mode.enabled' must be boolean.")
