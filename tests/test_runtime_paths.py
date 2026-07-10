from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.app_paths as app_paths
import core.config_store as config_store


def _set_platform_dirs(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[Path, Path, Path]:
    config = tmp_path / "platform" / "config"
    data = tmp_path / "platform" / "data"
    cache = tmp_path / "platform" / "cache"
    directories = SimpleNamespace(
        user_config_path=config,
        user_data_path=data,
        user_cache_path=cache,
    )
    monkeypatch.setattr(app_paths, "_platform_dirs", lambda: directories)
    return config, data, cache


def test_runtime_layout_uses_platform_locations_and_keeps_resources_in_bundle(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "bundle"
    resource_config = bundle / "config"
    preset = resource_config / "presets" / "default.json"
    preset.parent.mkdir(parents=True)
    preset.write_text('{"name": "bundled"}\n', encoding="utf-8")
    original_resource = preset.read_bytes()

    monkeypatch.delenv(app_paths.PORTABLE_ENV_VAR, raising=False)
    monkeypatch.setattr(app_paths, "bundle_root", lambda: bundle)
    runtime_config, runtime_data, runtime_cache = _set_platform_dirs(monkeypatch, tmp_path)

    returned_config, returned_workdir = app_paths.ensure_runtime_layout()

    assert returned_config == resource_config
    assert returned_workdir == runtime_data
    assert app_paths.config_dir() == resource_config
    assert app_paths.user_config_dir() == runtime_config
    assert app_paths.user_data_dir() == runtime_data
    assert app_paths.user_cache_dir() == runtime_cache
    assert (runtime_data / "logs").is_dir()
    assert (runtime_cache / "temp").is_dir()
    assert not (runtime_config / "presets").exists()
    assert preset.read_bytes() == original_resource


def test_portable_layout_stays_under_application_workdir(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    application = tmp_path / "application"
    bundle = tmp_path / "bundle"
    resource_config = bundle / "config"
    resource_config.mkdir(parents=True)
    monkeypatch.setenv(app_paths.PORTABLE_ENV_VAR, "1")
    monkeypatch.setattr(app_paths, "app_root", lambda: application)
    monkeypatch.setattr(app_paths, "bundle_root", lambda: bundle)
    monkeypatch.setattr(
        app_paths,
        "_platform_dirs",
        lambda: pytest.fail("portable mode must not query platform directories"),
    )

    returned_config, returned_workdir = app_paths.ensure_runtime_layout()
    portable_workdir = application / "workdir"

    assert returned_config == resource_config
    assert returned_workdir == portable_workdir
    assert app_paths.user_config_dir() == portable_workdir
    assert app_paths.user_data_dir() == portable_workdir
    assert app_paths.user_cache_dir() == portable_workdir
    assert (portable_workdir / "logs").is_dir()
    assert (portable_workdir / "temp").is_dir()


def test_only_literal_one_enables_portable_mode(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    runtime_config, runtime_data, runtime_cache = _set_platform_dirs(monkeypatch, tmp_path)
    monkeypatch.setenv(app_paths.PORTABLE_ENV_VAR, "true")

    assert not app_paths.is_portable()
    assert app_paths.user_config_dir() == runtime_config
    assert app_paths.user_data_dir() == runtime_data
    assert app_paths.user_cache_dir() == runtime_cache


def test_app_config_write_is_fsynced_and_atomically_replaced(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_config = tmp_path / "runtime-config"
    resource_config = tmp_path / "read-only-resources"
    monkeypatch.setattr(config_store, "user_config_dir", lambda: runtime_config)

    events: list[str] = []
    real_replace = os.replace

    def record_fsync(_descriptor: int) -> None:
        events.append("fsync")

    def record_replace(source: str | Path, target: str | Path) -> None:
        source_path = Path(source)
        target_path = Path(target)
        assert source_path.parent == target_path.parent
        assert source_path.exists()
        events.append("replace")
        real_replace(source_path, target_path)

    monkeypatch.setattr(config_store.os, "fsync", record_fsync)
    monkeypatch.setattr(config_store.os, "replace", record_replace)

    path = config_store.save_app_config(
        resource_config,
        {"language": "zh_cn", "default_preset_name": "default_standard"},
    )

    assert path == runtime_config / config_store.APP_CONFIG_NAME
    assert events == ["fsync", "replace", "fsync"]
    assert json.loads(path.read_text(encoding="utf-8")) == {
        "language": "zh_cn",
        "default_preset_name": "default_standard",
        "remember_recent_paths": False,
    }
    assert list(runtime_config.glob(f".{config_store.APP_CONFIG_NAME}.*.tmp")) == []
    assert not resource_config.exists()


def test_failed_atomic_replace_preserves_existing_config_and_removes_temp_file(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    runtime_config = tmp_path / "runtime-config"
    resource_config = tmp_path / "resources"
    monkeypatch.setattr(config_store, "user_config_dir", lambda: runtime_config)
    path = config_store.save_app_config(resource_config, {"language": "en"})
    original = path.read_bytes()

    def fail_replace(_source: str | Path, _target: str | Path) -> None:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(config_store.os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        config_store.save_app_config(resource_config, {"language": "zh_cn"})

    assert path.read_bytes() == original
    assert list(runtime_config.glob(f".{config_store.APP_CONFIG_NAME}.*.tmp")) == []


def test_presets_dir_lookup_does_not_create_resource_directories(tmp_path: Path) -> None:
    resource_config = tmp_path / "bundle" / "config"

    assert config_store.presets_dir(resource_config) == resource_config / "presets"
    assert not resource_config.exists()
