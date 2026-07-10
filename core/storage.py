from __future__ import annotations

import contextlib
import hashlib
import os
import shutil
import tempfile
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path

from filelock import FileLock


class StorageError(OSError):
    pass


def resolved_path(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def paths_overlap(first: str | Path, second: str | Path) -> bool:
    left = resolved_path(first)
    right = resolved_path(second)
    return left == right or left.is_relative_to(right) or right.is_relative_to(left)


def validate_destination_outside_sources(destination: str | Path, sources: Iterable[str | Path]) -> None:
    target = resolved_path(destination)
    for source in sources:
        root = resolved_path(source)
        if target == root or target.is_relative_to(root):
            raise ValueError("Container path must not be inside an archived source directory")


def validate_disjoint_sources(public_sources: Iterable[str | Path], secret_sources: Iterable[str | Path]) -> None:
    for public in public_sources:
        for secret in secret_sources:
            if paths_overlap(public, secret):
                raise ValueError("Visible and encrypted source directories must not overlap")


@contextmanager
def container_lock(path: str | Path, *, timeout: float = 30.0) -> Iterator[None]:
    canonical = str(resolved_path(path)).encode("utf-8", "surrogatepass")
    digest = hashlib.sha256(canonical).hexdigest()
    user = str(getattr(os, "getuid", lambda: "user")())
    lock_root = Path(tempfile.gettempdir()) / "deniable-archiver-locks"
    lock_root.mkdir(parents=True, exist_ok=True)
    with FileLock(lock_root / f"{user}-{digest}.lock", timeout=timeout):
        yield


@contextmanager
def atomic_new_file(target: str | Path, *, replace_existing: bool) -> Iterator[Path]:
    destination = resolved_path(target)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = _new_temp_path(destination)
    try:
        yield temp_path
        sync_file(temp_path)
        if replace_existing:
            os.replace(temp_path, destination)
        else:
            _publish_new_file(temp_path, destination)
        sync_directory(destination.parent)
    except Exception:
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)
        raise


@contextmanager
def atomic_copy_for_update(target: str | Path) -> Iterator[Path]:
    destination = resolved_path(target)
    if not destination.exists() or not destination.is_file() or destination.is_symlink():
        raise FileNotFoundError(f"Container file does not exist or is unsafe: {destination}")
    temp_path = _new_temp_path(destination)
    try:
        shutil.copyfile(destination, temp_path)
        yield temp_path
        sync_file(temp_path)
        os.replace(temp_path, destination)
        sync_directory(destination.parent)
    except Exception:
        with contextlib.suppress(OSError):
            temp_path.unlink(missing_ok=True)
        raise


@contextmanager
def temporary_output_directory(destination: str | Path) -> Iterator[Path]:
    target = resolved_path(destination)
    target.parent.mkdir(parents=True, exist_ok=True)
    raw = tempfile.mkdtemp(prefix=f".{target.name}.", suffix=".extract", dir=target.parent)
    temp_path = Path(raw)
    try:
        yield temp_path
    finally:
        if temp_path.exists():
            shutil.rmtree(temp_path, ignore_errors=True)


def publish_directory(temp_path: Path, destination: str | Path, *, replace: bool = False) -> Path:
    target = resolved_path(destination)
    if not temp_path.exists() or not temp_path.is_dir():
        raise StorageError("Temporary extraction directory is missing")

    backup: Path | None = None
    if target.exists():
        if target.is_symlink() or not target.is_dir():
            raise FileExistsError(f"Output path already exists and is not a safe directory: {target}")
        if not replace and any(target.iterdir()):
            raise FileExistsError(f"Output directory is not empty: {target}")
        if replace:
            backup = _new_backup_path(target)
            os.replace(target, backup)
        else:
            target.rmdir()

    try:
        os.replace(temp_path, target)
        sync_directory(target.parent)
    except Exception:
        if backup is not None and backup.exists() and not target.exists():
            os.replace(backup, target)
        raise
    if backup is not None:
        with contextlib.suppress(OSError):
            shutil.rmtree(backup)
    return target


def sync_file(path: str | Path) -> None:
    with Path(path).open("rb") as handle:
        os.fsync(handle.fileno())


def sync_directory(path: str | Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


def _new_temp_path(destination: Path) -> Path:
    descriptor, raw = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
    os.close(descriptor)
    return Path(raw)


def _publish_new_file(temp_path: Path, destination: Path) -> None:
    if os.name == "nt":
        os.rename(temp_path, destination)
        return
    os.link(temp_path, destination)
    with contextlib.suppress(OSError):
        temp_path.unlink()


def _new_backup_path(destination: Path) -> Path:
    descriptor, raw = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".backup", dir=destination.parent)
    os.close(descriptor)
    backup = Path(raw)
    backup.unlink()
    return backup
