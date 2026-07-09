from __future__ import annotations

from cli.cli_entry import run_cli


def main(argv: list[str] | None = None) -> int:
    return run_cli(argv)


if __name__ == "__main__":
    raise SystemExit(main())

