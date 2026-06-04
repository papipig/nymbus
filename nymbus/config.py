from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel


class Settings(BaseModel):
    external_llm_model: str = "anthropic/claude-opus-4"
    local_llm_model: Optional[str] = None
    local_llm_api_base: Optional[str] = None
    tier2_threshold: float = 0.85

    # Shell execution
    shell_confirm: bool = True
    shell_allow: list[str] = []
    shell_deny: list[str] = []

    # Custom detectors (loaded from nymbus.yaml)
    custom_patterns: list[str] = []   # list of regex strings
    custom_wordlists: list[str] = []  # list of literal strings to match

    @classmethod
    def load(cls) -> "Settings":
        data: dict = {}

        for candidate in [
            Path.cwd() / "nymbus.yaml",
            Path.home() / ".config" / "nb" / "nymbus.yaml",
        ]:
            if candidate.exists():
                with candidate.open() as f:
                    raw = yaml.safe_load(f) or {}
                # Flatten shell sub-key
                shell = raw.pop("shell", {})
                raw["shell_confirm"] = shell.get("confirm", True)
                raw["shell_allow"] = shell.get("allow", [])
                raw["shell_deny"] = shell.get("deny", [])
                data = raw
                break

        # Environment variable overrides (NB_ prefix)
        _str_keys = ("external_llm_model", "local_llm_model", "local_llm_api_base")
        for key in _str_keys:
            env_val = os.environ.get(f"NB_{key.upper()}")
            if env_val is not None:
                data[key] = env_val

        _float_keys = ("tier2_threshold",)
        for key in _float_keys:
            env_val = os.environ.get(f"NB_{key.upper()}")
            if env_val is not None:
                data[key] = float(env_val)

        return cls(**{k: v for k, v in data.items() if k in cls.model_fields})


_instance: Optional[Settings] = None


def get_settings() -> Settings:
    global _instance
    if _instance is None:
        _instance = Settings.load()
    return _instance
