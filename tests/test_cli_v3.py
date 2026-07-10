from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

import cli.cli_entry as cli_entry
from core.archiver import (
    NO_MATCH_MESSAGE,
    SUCCESS_MESSAGE,
    ConflictPolicy,
    ExtractionResult,
    ExtractionStatus,
)
from core.layout import MIB


@pytest.fixture(autouse=True)
def isolated_cli(monkeypatch):
    monkeypatch.setattr(cli_entry, "ensure_runtime_layout", lambda: None)


@dataclass
class RecordingArchiver:
    initialize_calls: list[tuple[tuple[object, ...], dict[str, object]]] = field(default_factory=list)
    write_calls: list[tuple[tuple[object, ...], dict[str, object]]] = field(default_factory=list)
    extract_calls: list[tuple[tuple[object, ...], dict[str, object]]] = field(default_factory=list)
    extraction_result: ExtractionResult = field(
        default_factory=lambda: ExtractionResult(SUCCESS_MESSAGE, ExtractionStatus.EXTRACTED, Path("output"))
    )

    def initialize_container(self, *args, **kwargs) -> None:
        self.initialize_calls.append((args, kwargs))

    def write_payload(self, *args, **kwargs) -> None:
        self.write_calls.append((args, kwargs))

    def extract_payload(self, *args, **kwargs) -> ExtractionResult:
        self.extract_calls.append((args, kwargs))
        output = args[2]
        policy = kwargs["conflict_policy"]
        if output.exists() and any(output.iterdir()) and policy is ConflictPolicy.FAIL:
            raise FileExistsError(f"Output directory is not empty: {output}")
        return self.extraction_result


def _install_archiver(monkeypatch, archiver: RecordingArchiver) -> None:
    monkeypatch.setattr(cli_entry, "DeniableArchiver", lambda: archiver)


def test_init_defaults_to_raw_and_sources_do_not_enable_wrapper(monkeypatch, tmp_path, capsys):
    archiver = RecordingArchiver()
    _install_archiver(monkeypatch, archiver)
    raw_container = tmp_path / "raw.darc"

    assert cli_entry.run_cli(["init", str(raw_container), "--size-mb", "1"]) == 0
    assert archiver.initialize_calls[0][1]["zip_wrapper"] is None

    visible = tmp_path / "visible"
    visible.mkdir()
    assert cli_entry.run_cli(["init", str(tmp_path / "implicit.zip"), "--visible-source", str(visible)]) == 1
    assert len(archiver.initialize_calls) == 1
    assert "require --zip-wrapper" in capsys.readouterr().err


def test_zip_wrapper_requires_source_through_core_validation(tmp_path, capsys):
    zip_container = tmp_path / "wrapper.zip"

    assert cli_entry.run_cli(["init", str(zip_container), "--size-mb", "1", "--zip-wrapper"]) == 1
    assert "requires at least one source entry" in capsys.readouterr().err
    assert not zip_container.exists()


def test_init_refuses_existing_destination_unless_forced(monkeypatch, tmp_path, capsys):
    archiver = RecordingArchiver()
    _install_archiver(monkeypatch, archiver)
    container = tmp_path / "existing.darc"
    container.write_bytes(b"existing")

    assert cli_entry.run_cli(["init", str(container), "--size-mb", "1"]) == 1
    assert not archiver.initialize_calls
    assert "use --force" in capsys.readouterr().err
    assert container.read_bytes() == b"existing"

    assert cli_entry.run_cli(["init", str(container), "--size-mb", "1", "--force"]) == 0
    assert len(archiver.initialize_calls) == 1


def test_extract_force_maps_to_replace_policy(monkeypatch, tmp_path, capsys):
    archiver = RecordingArchiver()
    _install_archiver(monkeypatch, archiver)
    monkeypatch.setattr(cli_entry.getpass, "getpass", lambda _prompt: "strong password")
    output = tmp_path / "output"
    output.mkdir()
    (output / "existing.txt").write_text("keep", encoding="utf-8")
    base_args = ["extract", str(tmp_path / "vault.darc"), str(output)]

    assert cli_entry.run_cli(base_args) == 1
    assert archiver.extract_calls[0][1]["conflict_policy"] is ConflictPolicy.FAIL
    assert "not empty" in capsys.readouterr().err

    assert cli_entry.run_cli([*base_args, "--force"]) == 0
    assert archiver.extract_calls[1][1]["conflict_policy"] is ConflictPolicy.REPLACE


@pytest.mark.parametrize("command", ["write", "extract"])
def test_empty_payload_password_is_rejected_before_core_call(monkeypatch, tmp_path, capsys, command):
    archiver = RecordingArchiver()
    _install_archiver(monkeypatch, archiver)
    monkeypatch.setattr(cli_entry.getpass, "getpass", lambda _prompt: "")
    if command == "write":
        args = ["write", str(tmp_path / "vault.darc"), str(tmp_path / "source"), "--slot", "0"]
    else:
        args = ["extract", str(tmp_path / "vault.darc"), str(tmp_path / "output")]

    assert cli_entry.run_cli(args) == 1
    assert "Password must not be empty" in capsys.readouterr().err
    assert not archiver.write_calls
    assert not archiver.extract_calls


def test_no_match_uses_generic_message_and_distinct_exit_code(monkeypatch, tmp_path, capsys):
    archiver = RecordingArchiver(
        extraction_result=ExtractionResult("slot-specific detail", ExtractionStatus.NO_MATCH, None)
    )
    _install_archiver(monkeypatch, archiver)
    monkeypatch.setattr(cli_entry.getpass, "getpass", lambda _prompt: "wrong password")
    output = tmp_path / "output"

    result = cli_entry.run_cli(["extract", str(tmp_path / "vault.darc"), str(output)])

    captured = capsys.readouterr()
    assert result == cli_entry.NO_MATCH_EXIT_CODE
    assert result not in {0, 1, 2}
    assert captured.out.strip() == NO_MATCH_MESSAGE
    assert captured.err == ""
    assert not output.exists()
    assert not (output / "decrypted_raw.bin").exists()


def test_equal_and_custom_layout_arguments_are_preserved(monkeypatch, tmp_path):
    archiver = RecordingArchiver()
    _install_archiver(monkeypatch, archiver)
    monkeypatch.setattr(cli_entry.getpass, "getpass", lambda _prompt: "strong password")
    container = tmp_path / "vault.darc"
    source = tmp_path / "source"

    assert cli_entry.run_cli(["write", str(container), str(source), "--slot", "1", "--slots", "8"]) == 0
    assert archiver.write_calls[0][1]["slot_count"] == 8
    assert archiver.write_calls[0][1]["layout"] is None

    assert cli_entry.run_cli(["extract", str(container), str(tmp_path / "output"), "--slot-sizes", "1,2,3"]) == 0
    assert archiver.extract_calls[0][1]["slot_count"] is None
    assert archiver.extract_calls[0][1]["layout"] == (MIB, 2 * MIB, 3 * MIB)


def test_equal_and_custom_layout_flags_are_strictly_mutually_exclusive(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        cli_entry.run_cli(
            [
                "write",
                str(tmp_path / "vault.darc"),
                str(tmp_path / "source"),
                "--slot",
                "0",
                "--slots",
                "4",
                "--slot-sizes",
                "1,1,1,1",
            ]
        )

    assert error.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err
