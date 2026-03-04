"""Runtime configuration and filesystem paths."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from platformdirs import user_state_dir

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib


DEFAULT_UNLOCK_TIMEOUT_SECONDS = 900


@dataclass(frozen=True)
class AppPaths:
    state_dir: Path
    db_path: Path
    config_path: Path


@dataclass(frozen=True)
class AppConfig:
    unlock_timeout_seconds: int = DEFAULT_UNLOCK_TIMEOUT_SECONDS
    preferred_backend: str = "auto"


def get_app_paths() -> AppPaths:
    state_dir_override = os.getenv("PYSECRET_STATE_DIR")
    if state_dir_override:
        state_dir = Path(state_dir_override).expanduser()
    else:
        state_dir = Path(user_state_dir("pysecret", "pysecret"))
    db_path = state_dir / "secrets.db"
    config_path = state_dir / "config.toml"
    return AppPaths(state_dir=state_dir, db_path=db_path, config_path=config_path)


def ensure_state_dir(paths: AppPaths) -> None:
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(paths.state_dir, 0o700)
    except PermissionError:
        # Some platforms/filesystems may not allow chmod.
        pass


def load_config(paths: AppPaths) -> AppConfig:
    if not paths.config_path.exists():
        save_config(paths, AppConfig())
        return AppConfig()

    raw: dict[str, Any]
    with paths.config_path.open("rb") as f:
        raw = tomllib.load(f)

    timeout = int(raw.get("unlock_timeout_seconds", DEFAULT_UNLOCK_TIMEOUT_SECONDS))
    preferred_backend = str(raw.get("preferred_backend", "auto"))
    return AppConfig(unlock_timeout_seconds=timeout, preferred_backend=preferred_backend)


def save_config(paths: AppPaths, config: AppConfig) -> None:
    ensure_state_dir(paths)
    content = (
        f"unlock_timeout_seconds = {config.unlock_timeout_seconds}\n"
        f"preferred_backend = \"{config.preferred_backend}\"\n"
    )
    paths.config_path.write_text(content, encoding="utf-8")
    try:
        os.chmod(paths.config_path, 0o600)
    except PermissionError:
        pass
