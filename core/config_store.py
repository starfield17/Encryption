from __future__ import annotations

import json
import re
from pathlib import Path
from threading import RLock
from typing import Any, Callable

from core.app_paths import workdir_dir


APP_CONFIG_NAME = "app_config.json"
_APP_CONFIG_LOCK = RLock()


def presets_dir(config_dir: Path) -> Path:
    path = config_dir / "presets"
    path.mkdir(parents=True, exist_ok=True)
    return path


def app_config_path(config_dir: Path) -> Path:
    del config_dir
    runtime_workdir = workdir_dir()
    runtime_workdir.mkdir(parents=True, exist_ok=True)
    return runtime_workdir / APP_CONFIG_NAME


def _preset_path(name: str, config_dir: Path) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("Preset names may only contain letters, numbers, dots, underscores, and dashes.")
    return presets_dir(config_dir) / f"{name}.json"


def _default_app_config() -> dict[str, Any]:
    return {
        "language": "zh_cn",
        "default_preset_name": "default_standard",
        "recent_paths": [],
    }


def list_presets(config_dir: Path) -> list[str]:
    return sorted(path.stem for path in presets_dir(config_dir).glob("*.json"))


def load_preset(name: str, config_dir: Path) -> dict[str, Any]:
    path = _preset_path(name, config_dir)
    if not path.exists():
        raise FileNotFoundError(f"Preset does not exist: {name}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Preset is not an object: {name}")
    return data


def _load_app_config_unlocked(config_dir: Path) -> dict[str, Any]:
    path = app_config_path(config_dir)
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return {**_default_app_config(), **data}
    return _default_app_config()


def _save_app_config_unlocked(config_dir: Path, data: dict[str, Any]) -> Path:
    path = app_config_path(config_dir)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


def load_app_config(config_dir: Path) -> dict[str, Any]:
    with _APP_CONFIG_LOCK:
        return _load_app_config_unlocked(config_dir)


def save_app_config(config_dir: Path, data: dict[str, Any]) -> Path:
    with _APP_CONFIG_LOCK:
        return _save_app_config_unlocked(config_dir, data)


def update_app_config(
    config_dir: Path,
    updater: Callable[[dict[str, Any]], dict[str, Any] | None],
) -> Path:
    with _APP_CONFIG_LOCK:
        data = _load_app_config_unlocked(config_dir)
        updated = updater(data)
        if updated is not None:
            data = updated
        return _save_app_config_unlocked(config_dir, data)

