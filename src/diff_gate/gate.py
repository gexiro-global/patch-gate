"""Policy and execution gates."""

from __future__ import annotations

import fnmatch
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Optional, Sequence

from .parser import DiffParseError, parse_diff


@dataclass(frozen=True)
class GateResult:
    mode: str
    status: str
    exit_code: int
    root: str
    paths: List[Dict[str, object]]
    checks: Dict[str, object]
    errors: List[str]

    def as_dict(self) -> Dict[str, object]:
        return {"mode": self.mode, "status": self.status, "exit_code": self.exit_code,
                "root": self.root, "paths": self.paths, "checks": self.checks,
                "errors": self.errors}


def _matches(path: str, patterns: Sequence[str]) -> Optional[str]:
    def match_parts(path_parts: Sequence[str], pattern_parts: Sequence[str]) -> bool:
        if not pattern_parts:
            return not path_parts
        if pattern_parts[0] == "**":
            return match_parts(path_parts, pattern_parts[1:]) or bool(path_parts) and match_parts(
                path_parts[1:], pattern_parts)
        return bool(path_parts) and fnmatch.fnmatchcase(path_parts[0], pattern_parts[0]) and match_parts(
            path_parts[1:], pattern_parts[1:])

    path_parts = path.split("/")
    for pattern in patterns:
        if pattern and match_parts(path_parts, pattern.split("/")):
            return pattern
    return None


def _path_verdict(root: Path, path: str, allow: Sequence[str], deny: Sequence[str]) -> Dict[str, object]:
    verdict: Dict[str, object] = {"path": path, "safe": False, "reason": ""}
    p = PurePosixPath(path)
    if not path or p.is_absolute() or os.path.isabs(path):
        verdict["reason"] = "absolute or empty path"
        return verdict
    if "\\" in path:
        verdict["reason"] = "backslash path separators are ambiguous"
        return verdict
    if any(part in ("", ".", "..") for part in p.parts):
        verdict["reason"] = "path contains empty, dot, or parent component"
        return verdict
    target = root.joinpath(*p.parts)
    cursor = root
    try:
        for part in p.parts:
            cursor = cursor / part
            try:
                mode = cursor.lstat().st_mode
            except FileNotFoundError:
                continue
            if stat.S_ISLNK(mode):
                verdict["reason"] = "path traverses a symbolic link"
                return verdict
    except OSError as exc:
        verdict["reason"] = "cannot safely inspect path: %s" % exc
        return verdict
    try:
        relative = target.resolve(strict=False).relative_to(root)
    except (OSError, ValueError, RuntimeError):
        verdict["reason"] = "resolved path escapes workspace root"
        return verdict
    if relative.as_posix() != path:
        verdict["reason"] = "resolved path differs from lexical path"
        return verdict
    denied = _matches(path, deny)
    if denied is not None:
        verdict["reason"] = "denied by glob: %s" % denied
        return verdict
    allowed = _matches(path, allow)
    if allowed is None:
        verdict["reason"] = "not matched by any allow glob"
        return verdict
    verdict["safe"] = True
    verdict["reason"] = "allowed by glob: %s" % allowed
    return verdict


def _git(root: Path, args: Iterable[str], patch: Optional[bytes] = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(root), input=patch,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)


def run_gate(patch: bytes, *, mode: str = "inspect", root: Path = Path("."), strip: int = 1,
             allow: Sequence[str] = ("**",), deny: Sequence[str] = (),
             allow_dirty: bool = False) -> GateResult:
    """Inspect, check, or atomically apply a patch after all gates pass."""
    if mode not in ("inspect", "check", "apply"):
        raise ValueError("mode must be inspect, check, or apply")
    resolved_root = root.resolve()
    checks: Dict[str, object] = {"parsed": False, "policy": False, "git_available": None,
                                 "git_check": None, "clean_tree": None, "applied": False}
    try:
        parsed = parse_diff(patch, strip=strip)
    except DiffParseError as exc:
        return GateResult(mode, "parse_error", 2, str(resolved_root), [], checks, [str(exc)])
    checks["parsed"] = True
    verdicts = [_path_verdict(resolved_root, path, allow, deny) for path in parsed.paths]
    rejected = [v for v in verdicts if not v["safe"]]
    if rejected:
        return GateResult(mode, "rejected", 1, str(resolved_root), verdicts, checks,
                          [str(v["path"]) + ": " + str(v["reason"]) for v in rejected])
    checks["policy"] = True
    if mode == "inspect":
        return GateResult(mode, "safe", 0, str(resolved_root), verdicts, checks, [])
    if not resolved_root.is_dir():
        return GateResult(mode, "usage_error", 2, str(resolved_root), verdicts, checks,
                          ["workspace root is not a directory"])
    checks["git_available"] = shutil.which("git") is not None
    if not checks["git_available"]:
        return GateResult(mode, "usage_error", 2, str(resolved_root), verdicts, checks,
                          ["git executable is required for check/apply"])
    inside = _git(resolved_root, ["rev-parse", "--is-inside-work-tree"])
    if inside.returncode != 0 or inside.stdout.strip() != b"true":
        return GateResult(mode, "usage_error", 2, str(resolved_root), verdicts, checks,
                          ["workspace root is not inside a Git work tree"])
    top = _git(resolved_root, ["rev-parse", "--show-toplevel"])
    try:
        git_root = Path(os.fsdecode(top.stdout.rstrip(b"\r\n"))).resolve()
    except (OSError, ValueError):
        git_root = Path()
    if top.returncode != 0 or git_root != resolved_root:
        return GateResult(mode, "usage_error", 2, str(resolved_root), verdicts, checks,
                          ["workspace root must be the Git work-tree root"])
    # Revalidate immediately before invoking Git to narrow the symlink race window.
    verdicts = [_path_verdict(resolved_root, path, allow, deny) for path in parsed.paths]
    if any(not v["safe"] for v in verdicts):
        return GateResult(mode, "rejected", 1, str(resolved_root), verdicts, checks,
                          ["path changed during validation"])
    check = _git(resolved_root, ["apply", "--check", "-p%d" % strip, "--"], patch)
    checks["git_check"] = check.returncode == 0
    if check.returncode:
        message = check.stderr.decode("utf-8", "replace").strip() or "git apply --check failed"
        return GateResult(mode, "rejected", 1, str(resolved_root), verdicts, checks, [message])
    if mode == "check":
        return GateResult(mode, "safe", 0, str(resolved_root), verdicts, checks, [])
    status = _git(resolved_root, ["status", "--porcelain", "--untracked-files=all"])
    if status.returncode:
        return GateResult(mode, "usage_error", 2, str(resolved_root), verdicts, checks,
                          [status.stderr.decode("utf-8", "replace").strip() or "cannot inspect Git status"])
    clean = not bool(status.stdout)
    checks["clean_tree"] = clean
    if not clean and not allow_dirty:
        return GateResult(mode, "rejected", 1, str(resolved_root), verdicts, checks,
                          ["working tree is dirty; use --allow-dirty to override"])
    verdicts = [_path_verdict(resolved_root, path, allow, deny) for path in parsed.paths]
    if any(not v["safe"] for v in verdicts):
        return GateResult(mode, "rejected", 1, str(resolved_root), verdicts, checks,
                          ["path changed before apply"])
    applied = _git(resolved_root, ["apply", "-p%d" % strip, "--"], patch)
    if applied.returncode:
        return GateResult(mode, "rejected", 1, str(resolved_root), verdicts, checks,
                          [applied.stderr.decode("utf-8", "replace").strip() or "git apply failed"])
    checks["applied"] = True
    return GateResult(mode, "applied", 0, str(resolved_root), verdicts, checks, [])
