"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path
from typing import List, Optional


_MAX_PATCH_BYTES = 64 * 1024 * 1024


class _UsageError(ValueError):
    pass


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(message)


def _parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(prog="diff-gate", description="Gate an untrusted unified diff")
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
    try:
        args = _parser().parse_args(argv)
        if args.strip < 0:
            raise _UsageError("--strip must be non-negative")
    except _UsageError as exc:
        payload = {"mode": "unknown", "status": "usage_error", "exit_code": 2,
                   "root": "", "paths": [], "checks": {}, "errors": [str(exc)]}
        _emit(payload, "json")
        return 2
    try:
        resolved_root = Path(args.root).resolve()
        if args.patch == "-":
            patch = sys.stdin.buffer.read(_MAX_PATCH_BYTES + 1)
        else:
            candidate = Path(args.patch)
            if not candidate.is_absolute():
                candidate = Path.cwd() / candidate
            candidate = candidate.absolute()
            try:
                relative = candidate.relative_to(resolved_root)
            except ValueError:
                raise OSError("patch file must be inside the workspace root")
            if any(part in ("", ".", "..") for part in relative.parts):
                raise OSError("patch file path contains a dot or parent component")
            cursor = resolved_root
            for part in relative.parts:
                cursor /= part
                mode = cursor.lstat().st_mode
                if stat.S_ISLNK(mode):
                    raise OSError("patch file must not traverse a symbolic link")
            if not stat.S_ISREG(candidate.stat().st_mode):
                raise OSError("patch input must be a regular file")
            if candidate.stat().st_size > _MAX_PATCH_BYTES:
                raise OSError("patch exceeds 64 MiB safety limit")
            patch = candidate.read_bytes()
    except (OSError, ValueError, RuntimeError) as exc:
        payload = {"mode": args.mode, "status": "usage_error", "exit_code": 2,
                   "root": str(args.root), "paths": [], "checks": {},
                   "errors": ["cannot read patch: %s" % exc]}
        _emit(payload, args.format)
        return 2
    from .gate import run_gate
    result = run_gate(patch, mode=args.mode, root=Path(args.root), strip=args.strip,
                      allow=args.allow or ("**",), deny=args.deny,
                      allow_dirty=args.allow_dirty)
    _emit(result.as_dict(), args.format)
    return result.exit_code
