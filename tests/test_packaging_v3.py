from __future__ import annotations

import importlib.util
import runpy
import sys
import tomllib
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts" / "build_pyinstaller.py"
SPEC_FILE = ROOT / "packaging" / "deniable_archiver.spec"


def _load_build_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("build_pyinstaller", BUILD_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_spec(spec_path: Path) -> dict[str, object]:
    captures: dict[str, object] = {}

    def analysis(*args: object, **kwargs: object) -> SimpleNamespace:
        captures["analysis"] = kwargs
        return SimpleNamespace(pure=[], scripts=[], binaries=[], datas=kwargs["datas"])

    def exe(*args: object, **kwargs: object) -> dict[str, object]:
        captures["exe"] = kwargs
        return kwargs

    def collect(*args: object, **kwargs: object) -> dict[str, object]:
        captures["collect"] = kwargs
        return kwargs

    runpy.run_path(
        str(SPEC_FILE),
        init_globals={
            "SPECPATH": str(spec_path.parent),
            "Analysis": analysis,
            "PYZ": lambda *args, **kwargs: object(),
            "EXE": exe,
            "COLLECT": collect,
        },
    )
    return captures


def test_script_mode_collects_application_modules_and_data(tmp_path, monkeypatch):
    build_script = _load_build_script()
    (tmp_path / "config").mkdir()
    fonts = tmp_path / "packaging" / "assets" / "fonts"
    fonts.mkdir(parents=True)
    monkeypatch.setattr(build_script, "project_root", lambda: tmp_path)

    args = SimpleNamespace(
        onefile=True,
        windowed=True,
        name=None,
        icon=None,
        version_file=None,
        clean=False,
        upx=False,
    )
    command, _ = build_script._pyinstaller_command(args)

    collected = [command[index + 1] for index, value in enumerate(command) if value == "--collect-submodules"]
    assert collected == ["cli", "core", "gui"]
    data_args = [command[index + 1] for index, value in enumerate(command) if value == "--add-data"]
    separator = ";" if sys.platform.startswith("win") else ":"
    assert data_args == [f"{tmp_path / 'config'}{separator}config", f"{fonts}{separator}fonts"]
    assert "--onefile" in command
    assert "--windowed" in command
    assert "--noupx" in command
    assert command[command.index("--specpath") + 1] == str(tmp_path / "build")


def test_dry_run_does_not_invoke_pyinstaller(monkeypatch, capsys):
    build_script = _load_build_script()

    def unexpected_build(*args: object, **kwargs: object) -> None:
        pytest.fail("dry-run invoked PyInstaller")

    monkeypatch.setattr(build_script.subprocess, "run", unexpected_build)

    assert build_script.main(["--dry-run", "--onefile", "--windowed"]) == 0
    output = capsys.readouterr().out
    assert "--collect-submodules cli" in output
    assert "--collect-submodules core" in output
    assert "--collect-submodules gui" in output
    assert "--noupx" in output
    assert "no build was run" in output


def test_spec_command_leaves_upx_control_to_the_spec():
    build_script = _load_build_script()
    args = SimpleNamespace(
        onefile=False,
        windowed=False,
        name=None,
        clean=False,
        upx=False,
    )

    command, _ = build_script._pyinstaller_command(args)

    assert str(SPEC_FILE) in command
    assert "--noupx" not in command


def test_upx_requires_explicit_opt_in(tmp_path, monkeypatch, capsys):
    build_script = _load_build_script()
    captured: dict[str, object] = {}

    def record_build(command: list[str], **kwargs: object) -> None:
        captured["command"] = command
        captured.update(kwargs)

    monkeypatch.setattr(build_script.subprocess, "run", record_build)
    monkeypatch.setattr(build_script, "dist_dir", lambda: tmp_path / "dist")

    assert build_script.main(["--upx"]) == 0
    output = capsys.readouterr().out
    assert "--noupx" not in output
    assert str(SPEC_FILE) in captured["command"]
    assert captured["env"]["DENIABLE_ARCHIVER_ENABLE_UPX"] == "1"


def test_spec_mode_matches_data_and_module_collection_and_disables_upx(tmp_path, monkeypatch):
    packaging_dir = tmp_path / "packaging"
    fonts = packaging_dir / "assets" / "fonts"
    fonts.mkdir(parents=True)
    (tmp_path / "config").mkdir()
    monkeypatch.delenv("DENIABLE_ARCHIVER_ENABLE_UPX", raising=False)

    captures = _run_spec(packaging_dir / SPEC_FILE.name)
    analysis = captures["analysis"]
    assert isinstance(analysis, dict)
    assert analysis["datas"] == [(str(tmp_path / "config"), "config"), (str(fonts), "fonts")]
    hiddenimports = analysis["hiddenimports"]
    assert isinstance(hiddenimports, list)
    assert {"cli.cli_entry", "core.archiver", "gui.gui_entry"} <= set(hiddenimports)
    assert captures["exe"]["upx"] is False
    assert captures["collect"]["upx"] is False

    monkeypatch.setenv("DENIABLE_ARCHIVER_ENABLE_UPX", "1")
    captures = _run_spec(packaging_dir / SPEC_FILE.name)
    assert captures["exe"]["upx"] is True
    assert captures["collect"]["upx"] is True


def test_project_declares_supported_python_and_security_tooling():
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["requires-python"] == ">=3.11"
    assert metadata["tool"]["ruff"]["target-version"] == "py311"

    dev_requirements = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
    assert any(requirement.startswith("pip-audit") for requirement in dev_requirements)
