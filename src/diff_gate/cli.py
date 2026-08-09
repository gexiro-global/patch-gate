"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="diff-gate", description="Gate an untrusted unified diff")
    parser.add_argument("mode", choices=("inspect", "check", "apply"))
    parser.add_argument("patch", help="patch file, or - for standard input")
    parser.add_argument("--root", default=".", metavar="DIR")
    parser.add_argument("--strip", type=int, default=1, metavar="N")
    parser.add_argument("--allow", action="append", default=None, metavar="GLOB")
    parser.add_argument("--deny", action="append", default=[], metavar="GLOB")
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    return parser


def _emit(payload: dict, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, sort_keys=True, ensure_ascii=True, separators=(",", ":")))
        return
    print("%s: %s" % (payload["mode"], payload["status"]))
    for item in payload["paths"]:
        print("%s %s — %s" % ("ALLOW" if item["safe"] else "REJECT",
                              json.dumps(item["path"], ensure_ascii=True),
                              json.dumps(item["reason"], ensure_ascii=True)))
    for error in payload["errors"]:
        print("ERROR: " + json.dumps(error, ensure_ascii=True))


def main(argv: Optional[List[str]] = None) -> int:
    args = _parser().parse_args(argv)
    if args.strip < 0:
        _parser().error("--strip must be non-negative")
    try:
        patch = sys.stdin.buffer.read() if args.patch == "-" else Path(args.patch).read_bytes()
    except OSError as exc:
        payload = {"mode": args.mode, "status": "usage_error", "exit_code": 2,
                   "root": str(Path(args.root).resolve()), "paths": [], "checks": {},
                   "errors": ["cannot read patch: %s" % exc]}
        _emit(payload, args.format)
        return 2
    from .gate import run_gate
    result = run_gate(patch, mode=args.mode, root=Path(args.root), strip=args.strip,
                      allow=args.allow or ("**",), deny=args.deny,
                      allow_dirty=args.allow_dirty)
    _emit(result.as_dict(), args.format)
    return result.exit_code
