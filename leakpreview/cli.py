from __future__ import annotations

import argparse
import json
from pathlib import Path

from leakpreview.scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="leakpreview",
        description="Preview likely leaks in a folder before sharing it.",
    )
    parser.add_argument("path", help="Directory to scan")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit machine-readable JSON output",
    )
    parser.add_argument(
        "--max-size-mb",
        type=float,
        default=10.0,
        help="Flag files larger than this size in MB (default: 10)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    target = Path(args.path).expanduser().resolve()
    if not target.exists():
        parser.error(f"path does not exist: {target}")
    if not target.is_dir():
        parser.error(f"path is not a directory: {target}")
    if args.max_size_mb <= 0:
        parser.error("--max-size-mb must be greater than 0")

    result = scan_path(target, max_size_bytes=int(args.max_size_mb * 1024 * 1024))

    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(result.to_text())

    return 1 if result.has_findings else 0

