from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from core.app_paths import ensure_runtime_layout
from core.archiver import DEFAULT_CONTAINER_SIZE_MB, DEFAULT_SLOT_COUNT, DeniableArchiver


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deniable encryption archiver")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize a random container")
    init_parser.add_argument("container", help="Output container path")
    init_parser.add_argument("--size-mb", type=int, default=DEFAULT_CONTAINER_SIZE_MB, help="Container size in MiB")
    init_parser.add_argument("--slots", type=int, default=DEFAULT_SLOT_COUNT, help="Number of fixed-size slots")

    write_parser = subparsers.add_parser("write", help="Write a directory payload into a slot")
    write_parser.add_argument("container", help="Container path")
    write_parser.add_argument("source_dir", help="Source directory to archive")
    write_parser.add_argument("--slot", type=int, required=True, help="Slot index to overwrite")
    write_parser.add_argument("--slots", type=int, default=DEFAULT_SLOT_COUNT, help="Number of fixed-size slots")
    write_parser.add_argument("--no-compress", action="store_true", help="Store files without ZIP compression")

    extract_parser = subparsers.add_parser("extract", help="Extract a matching payload or a blind raw dump")
    extract_parser.add_argument("container", help="Container path")
    extract_parser.add_argument("output_dir", help="Output directory")
    extract_parser.add_argument("--slots", type=int, default=DEFAULT_SLOT_COUNT, help="Number of fixed-size slots")

    return parser


def _prompt_new_password() -> str:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise ValueError("Passwords do not match")
    return password


def run_cli(argv: list[str] | None = None) -> int:
    ensure_runtime_layout()
    parser = _build_parser()
    args = parser.parse_args(argv)
    archiver = DeniableArchiver()

    try:
        if args.command == "init":
            archiver.initialize_container(Path(args.container), size_mb=args.size_mb, slot_count=args.slots)
            print("Container initialized.")
            return 0
        if args.command == "write":
            password = _prompt_new_password()
            archiver.write_payload(
                Path(args.container),
                Path(args.source_dir),
                password,
                args.slot,
                slot_count=args.slots,
                compress=not args.no_compress,
            )
            print("Payload written.")
            return 0
        if args.command == "extract":
            password = getpass.getpass("Password: ")
            result = archiver.extract_payload(Path(args.container), password, Path(args.output_dir), slot_count=args.slots)
            print(result.message)
            return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    parser.error("unknown command")
    return 2
