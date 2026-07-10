from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Callable
from pathlib import Path
from threading import RLock
from typing import Any

from core.app_paths import user_config_dir

APP_CONFIG_NAME = "app_config.json"
_APP_CONFIG_LOCK = RLock()


def presets_dir(config_dir: Path) -> Path:
    return config_dir / "presets"


def app_config_path(config_dir: Path) -> Path:
    del config_dir
    runtime_config = user_config_dir()
    runtime_config.mkdir(parents=True, exist_ok=True)
    return runtime_config / APP_CONFIG_NAME


def _preset_path(name: str, config_dir: Path) -> Path:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
        raise ValueError("Preset names may only contain letters, numbers, dots, underscores, and dashes.")
    return presets_dir(config_dir) / f"{name}.json"


def _default_app_config() -> dict[str, Any]:
    return {
        "language": "en",
        "default_preset_name": "default_standard",
        "remember_recent_paths": False,
    }


def _normalize_app_config(data: dict[str, Any]) -> dict[str, Any]:
    normalized = {**_default_app_config(), **data}
    normalized.pop("recent_paths", None)
    normalized["remember_recent_paths"] = bool(normalized.get("remember_recent_paths", False))
    return normalized


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
            return _normalize_app_config(data)
    return _default_app_config()


def _save_app_config_unlocked(config_dir: Path, data: dict[str, Any]) -> Path:
    path = app_config_path(config_dir)
    data = _normalize_app_config(data)
    _write_json_atomic(path, data)
    return path


def _write_json_atomic(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=path.parent,
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(data, temporary_file, indent=2, ensure_ascii=False)
            temporary_file.write("\n")
            temporary_file.flush()
            os.fsync(temporary_file.fileno())

        os.replace(temporary_path, path)
        temporary_path = None
        _fsync_directory(path.parent)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


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
