from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from core.app_paths import ensure_runtime_layout
from core.archiver import (
    DEFAULT_CONTAINER_SIZE_MB,
    DEFAULT_SLOT_COUNT,
    DEFAULT_WRAPPER_ENTRY_NAME,
    ZIP_ENTRY_MODE_ARCHIVE,
    ZIP_ENTRY_MODE_FILES,
    DeniableArchiver,
    ZipWrapperOptions,
)
from core.layout import parse_slot_sizes_mib


def _add_layout_args(parser: argparse.ArgumentParser, *, default_slots: int | None = DEFAULT_SLOT_COUNT) -> None:
    parser.add_argument(
        "--slots",
        type=int,
        default=default_slots,
        help="Equal slot count (mutually exclusive with --slot-sizes)",
    )
    parser.add_argument(
        "--slot-sizes",
        help="Comma-separated slot sizes in MiB (layout secret; e.g. 10,40,30,20)",
    )


def _layout_kwargs(args: argparse.Namespace) -> dict[str, object]:
    if getattr(args, "slot_sizes", None):
        if args.slots is not None and args.slots != DEFAULT_SLOT_COUNT:
            # User set both explicitly — still prefer exclusive check via presence of slot_sizes
            pass
        layout = parse_slot_sizes_mib(args.slot_sizes)
        return {"layout": layout, "slot_count": None}
    slots = args.slots if args.slots is not None else DEFAULT_SLOT_COUNT
    return {"layout": None, "slot_count": slots}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Deniable encryption archiver")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialize a random container")
    init_parser.add_argument("container", help="Output container path")
    init_parser.add_argument("--size-mb", type=int, default=DEFAULT_CONTAINER_SIZE_MB, help="Container size in MiB")
    _add_layout_args(init_parser)
    wrapper_group = init_parser.add_mutually_exclusive_group()
    wrapper_group.add_argument(
        "--zip-wrapper",
        dest="zip_wrapper",
        action="store_true",
        default=True,
        help="Append a ZIP-compatible visible layer",
    )
    wrapper_group.add_argument(
        "--raw", dest="zip_wrapper", action="store_false", help="Create a raw random-looking container"
    )
    init_parser.add_argument("--visible-source", help="Directory to expose as ordinary ZIP entries")
    init_parser.add_argument("--passworded-entry-source", help="Directory to store as a passworded ZIP entry")
    init_parser.add_argument(
        "--passworded-entry-name", default=DEFAULT_WRAPPER_ENTRY_NAME, help="Name of the passworded ZIP entry"
    )
    init_parser.add_argument(
        "--passworded-entry-mode",
        choices=[ZIP_ENTRY_MODE_ARCHIVE, ZIP_ENTRY_MODE_FILES],
        default=ZIP_ENTRY_MODE_ARCHIVE,
        help="How to write passworded ZIP content",
    )

    write_parser = subparsers.add_parser("write", help="Write a directory payload into a slot")
    write_parser.add_argument("container", help="Container path")
    write_parser.add_argument("source_dir", help="Source directory to archive")
    write_parser.add_argument("--slot", type=int, required=True, help="Slot index to overwrite")
    _add_layout_args(write_parser)
    write_parser.add_argument("--no-compress", action="store_true", help="Store files without ZIP compression")

    extract_parser = subparsers.add_parser("extract", help="Extract a matching payload or a blind raw dump")
    extract_parser.add_argument("container", help="Container path")
    extract_parser.add_argument("output_dir", help="Output directory")
    _add_layout_args(extract_parser)

    return parser


def _prompt_new_password() -> str:
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        raise ValueError("Passwords do not match")
    return password


def _prompt_zip_entry_password() -> str:
    password = getpass.getpass("ZIP entry password: ")
    confirm = getpass.getpass("Confirm ZIP entry password: ")
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
            if args.slot_sizes and args.slots != DEFAULT_SLOT_COUNT:
                raise ValueError("Use either --slots or --slot-sizes, not both")
            if args.slot_sizes:
                layout = parse_slot_sizes_mib(args.slot_sizes)
                expected = args.size_mb * 1024 * 1024
                if sum(layout) != expected:
                    raise ValueError("Slot sizes in MiB must sum to --size-mb")
                layout_kwargs: dict[str, object] = {"layout": layout, "slot_count": None}
            else:
                layout_kwargs = {"layout": None, "slot_count": args.slots}

            zip_wrapper = None
            if args.zip_wrapper:
                zip_wrapper = ZipWrapperOptions(
                    enabled=True,
                    visible_source_dir=Path(args.visible_source) if args.visible_source else None,
                    encrypted_entry_source_dir=Path(args.passworded_entry_source)
                    if args.passworded_entry_source
                    else None,
                    encrypted_entry_name=args.passworded_entry_name,
                    encrypted_entry_password=_prompt_zip_entry_password() if args.passworded_entry_source else None,
                    encrypted_entry_mode=args.passworded_entry_mode,
                )
            archiver.initialize_container(
                Path(args.container),
                size_mb=args.size_mb,
                zip_wrapper=zip_wrapper,
                **layout_kwargs,  # type: ignore[arg-type]
            )
            print("Container initialized.")
            return 0
        if args.command == "write":
            if args.slot_sizes and args.slots != DEFAULT_SLOT_COUNT:
                raise ValueError("Use either --slots or --slot-sizes, not both")
            password = _prompt_new_password()
            layout_kwargs = _layout_kwargs(args)
            archiver.write_payload(
                Path(args.container),
                Path(args.source_dir),
                password,
                args.slot,
                compress=not args.no_compress,
                **layout_kwargs,  # type: ignore[arg-type]
            )
            print("Payload written.")
            return 0
        if args.command == "extract":
            if args.slot_sizes and args.slots != DEFAULT_SLOT_COUNT:
                raise ValueError("Use either --slots or --slot-sizes, not both")
            password = getpass.getpass("Password: ")
            layout_kwargs = _layout_kwargs(args)
            result = archiver.extract_payload(
                Path(args.container),
                password,
                Path(args.output_dir),
                **layout_kwargs,  # type: ignore[arg-type]
            )
            print(result.message)
            return 0
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    parser.error("unknown command")
    return 2
