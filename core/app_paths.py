from __future__ import annotations

import os
import sys
from pathlib import Path

from platformdirs import PlatformDirs

APP_NAME = "DeniableArchiver"
PORTABLE_ENV_VAR = "DARC_PORTABLE"


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def is_portable() -> bool:
    return os.environ.get(PORTABLE_ENV_VAR) == "1"


def source_root() -> Path:
    return Path(__file__).resolve().parent.parent


def bundle_root() -> Path:
    if is_frozen():
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            return Path(meipass).resolve()
        return Path(sys.executable).resolve().parent
    return source_root()


def app_root() -> Path:
    if is_frozen():
        return Path(sys.executable).resolve().parent
    return source_root()


def config_dir() -> Path:
    return bundle_root() / "config"


def _platform_dirs() -> PlatformDirs:
    return PlatformDirs(APP_NAME, appauthor=False)


def user_config_dir() -> Path:
    if is_portable():
        return app_root() / "workdir"
    return _platform_dirs().user_config_path


def user_data_dir() -> Path:
    if is_portable():
        return app_root() / "workdir"
    return _platform_dirs().user_data_path


def user_cache_dir() -> Path:
    if is_portable():
        return app_root() / "workdir"
    return _platform_dirs().user_cache_path


def workdir_dir() -> Path:
    return user_data_dir()


def ensure_runtime_layout() -> tuple[Path, Path]:
    resource_config = config_dir()
    runtime_config = user_config_dir()
    runtime_workdir = workdir_dir()
    runtime_cache = user_cache_dir()

    runtime_config.mkdir(parents=True, exist_ok=True)
    runtime_workdir.mkdir(parents=True, exist_ok=True)
    runtime_cache.mkdir(parents=True, exist_ok=True)

    (runtime_workdir / "logs").mkdir(parents=True, exist_ok=True)
    (runtime_cache / "temp").mkdir(parents=True, exist_ok=True)

    return resource_config, runtime_workdir
