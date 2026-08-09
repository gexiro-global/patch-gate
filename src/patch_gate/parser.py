"""Strict, byte-preserving parser for paths in Git/unified patches."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


class DiffParseError(ValueError):
    """The patch is malformed, ambiguous, or unsupported."""


@dataclass(frozen=True)
class ParsedDiff:
    paths: Tuple[str, ...]
    file_count: int


@dataclass
class _Section:
    diff_old: Optional[bytes] = None
    diff_new: Optional[bytes] = None
    old: Optional[bytes] = None
    new: Optional[bytes] = None
    rename_from: Optional[bytes] = None
    rename_to: Optional[bytes] = None
    copy_from: Optional[bytes] = None
    copy_to: Optional[bytes] = None
    new_mode: bool = False
    deleted_mode: bool = False
    old_mode: Optional[bytes] = None
    changed_mode: Optional[bytes] = None
    saw_body: bool = False
    hunks: int = 0
    index_seen: bool = False
    similarity_seen: bool = False
    dissimilarity_seen: bool = False


def _c_unquote(value: bytes) -> bytes:
    if not (value.startswith(b'"') and value.endswith(b'"')):
        raise DiffParseError("unterminated or malformed quoted path")
    data = value[1:-1]
    out = bytearray()
    i = 0
    escapes = {ord("a"): 7, ord("b"): 8, ord("t"): 9, ord("n"): 10,
               ord("v"): 11, ord("f"): 12, ord("r"): 13,
               ord('"'): 34, ord("\\"): 92}
    while i < len(data):
        byte = data[i]
        if byte != 92:
            out.append(byte)
            i += 1
            continue
        i += 1
        if i >= len(data):
            raise DiffParseError("trailing backslash in quoted path")
        byte = data[i]
        if byte in escapes:
            out.append(escapes[byte])
            i += 1
        elif 48 <= byte <= 55:
            digits = data[i:i + 3]
            if len(digits) != 3 or any(ch < 48 or ch > 55 for ch in digits):
                raise DiffParseError("Git path octal escapes must contain three digits")
            number = int(digits, 8)
            if number > 255:
                raise DiffParseError("Git path octal escape is out of byte range")
            out.append(number)
            i += 3
        else:
            raise DiffParseError("unknown C-style escape in quoted path")
    if b"\x00" in out:
        raise DiffParseError("NUL byte in path")
    return bytes(out)


def _one_path(value: bytes, *, timestamps: bool = False) -> bytes:
    value = value.rstrip(b"\r")
    if value.startswith(b'"'):
        # A header's quoted pathname must occupy the complete pathname field.
        escaped = False
        end = None
        for i in range(1, len(value)):
            if escaped:
                escaped = False
            elif value[i] == 92:
                escaped = True
            elif value[i] == 34:
                end = i + 1
                break
        if end is None:
            raise DiffParseError("unterminated quoted path")
        tail = value[end:]
        if tail and not (timestamps and tail.startswith(b"\t")):
            raise DiffParseError("ambiguous data after quoted path")
        return _c_unquote(value[:end])
    if timestamps:
        value = value.split(b"\t", 1)[0]
    if not value or (not timestamps and value != value.strip()):
        raise DiffParseError("empty or ambiguous path")
    if b"\x00" in value:
        raise DiffParseError("NUL byte in path")
    return value


def _two_git_paths(value: bytes) -> Tuple[bytes, bytes]:
    items: List[bytes] = []
    i = 0
    while i < len(value):
        while i < len(value) and value[i] == 32:
            i += 1
        if i == len(value):
            break
        if value[i] == 34:
            escaped = False
            start = i
            i += 1
            while i < len(value):
                if escaped:
                    escaped = False
                elif value[i] == 92:
                    escaped = True
                elif value[i] == 34:
                    i += 1
                    break
                i += 1
            else:
                raise DiffParseError("unterminated quoted diff --git path")
            items.append(_c_unquote(value[start:i]))
        else:
            start = i
            while i < len(value) and value[i] != 32:
                i += 1
            items.append(value[start:i])
    if len(items) != 2 or not all(items):
        raise DiffParseError("diff --git must contain exactly two unambiguous paths")
    return items[0], items[1]


def _strip(path: bytes, count: int) -> bytes:
    if path == b"/dev/null":
        return path
    if path.startswith(b"/"):
        raise DiffParseError("absolute path in patch")
    parts = path.split(b"/")
    if len(parts) <= count:
        raise DiffParseError("path has too few components for requested strip")
    return b"/".join(parts[count:])


def _validate_raw_path(path: bytes) -> None:
    """Reject names that are unsafe or have platform-dependent aliases."""
    if len(path) > 4096:
        raise DiffParseError("path exceeds 4096-byte safety limit")
    if b"\\" in path:
        raise DiffParseError("backslash path separators are ambiguous")
    for part in path.split(b"/"):
        if part not in (b"", b".", b"..") and part.rstrip(b" .") != part:
            raise DiffParseError("path component has trailing dot or space")


def _logical_extended(path: bytes) -> bytes:
    # Git extended headers are repository-relative and do not carry a/ or b/.
    if path.startswith(b"/"):
        raise DiffParseError("absolute path in extended header")
    return path


def _validate_mode(value: bytes, label: str) -> bytes:
    if re.fullmatch(br"[0-7]{6}", value) is None:
        raise DiffParseError("malformed %s" % label)
    file_type = int(value, 8) & 0o170000
    if file_type == 0o120000:
        raise DiffParseError("symbolic-link patches are unsupported")
    if file_type != 0o100000:
        raise DiffParseError("non-regular file modes are unsupported")
    return value


def _finish(section: _Section, strip: int) -> Iterable[bytes]:
    for raw in (section.diff_old, section.diff_new, section.old, section.new,
                section.rename_from, section.rename_to, section.copy_from, section.copy_to):
        if raw is not None and raw != b"/dev/null":
            _validate_raw_path(raw)
    rf = _logical_extended(section.rename_from) if section.rename_from is not None else None
    rt = _logical_extended(section.rename_to) if section.rename_to is not None else None
    cf = _logical_extended(section.copy_from) if section.copy_from is not None else None
    ct = _logical_extended(section.copy_to) if section.copy_to is not None else None

    if (section.old is None) != (section.new is None):
        raise DiffParseError("unpaired ---/+++ headers")
    if section.old == b"/dev/null" and section.new == b"/dev/null":
        raise DiffParseError("both content paths cannot be /dev/null")
    if section.similarity_seen and section.dissimilarity_seen:
        raise DiffParseError("section cannot have both similarity and dissimilarity headers")
    if (section.similarity_seen or section.dissimilarity_seen) and rf is None and cf is None:
        raise DiffParseError("similarity header requires rename or copy headers")
    if (rf is None) != (rt is None) or (cf is None) != (ct is None):
        raise DiffParseError("unpaired rename/copy headers")
    if rf is not None and cf is not None:
        raise DiffParseError("section cannot be both rename and copy")
    if section.new_mode and section.deleted_mode:
        raise DiffParseError("section cannot be both new and deleted")
    if (section.old_mode is None) != (section.changed_mode is None):
        raise DiffParseError("unpaired old/new mode headers")
    if (section.old is None and rf is None and cf is None and not section.new_mode
            and not section.deleted_mode and section.old_mode is None):
        raise DiffParseError("file section contains no patch operation")
    if (section.old is not None and section.hunks == 0 and rf is None and cf is None
            and not section.new_mode and not section.deleted_mode):
        raise DiffParseError("content headers require at least one hunk")
    if section.hunks and section.old is None:
        raise DiffParseError("hunk requires paired ---/+++ headers")
    if section.diff_old is None and section.old is None:
        raise DiffParseError("file section contains no usable path headers")

    extended_old, extended_new = (rf or cf), (rt or ct)
    if extended_old is not None:
        # Git applies rename/copy extended paths as repository-relative names even with -p0.
        # The a/ and b/ names are corroborating headers, not additional destinations.
        if section.diff_old is None:
            raise DiffParseError("rename/copy requires diff --git header")
        header_old = _strip(section.diff_old, 1)
        header_new = _strip(section.diff_new or b"", 1)
        if header_old != extended_old or header_new != extended_new:
            raise DiffParseError("rename/copy headers conflict with diff --git paths")
        if section.old is not None:
            content_old = (_strip(section.old, 1) if section.old != b"/dev/null" else section.old)
            content_new = (_strip(section.new or b"", 1) if section.new != b"/dev/null" else section.new)
            if content_old not in (b"/dev/null", extended_old) or content_new not in (b"/dev/null", extended_new):
                raise DiffParseError("rename/copy paths conflict with ---/+++ headers")
        return [extended_old, extended_new]

    if section.diff_old is not None:
        d_old, d_new = _strip(section.diff_old, strip), _strip(section.diff_new or b"", strip)
    else:
        d_old = d_new = None
    old = _strip(section.old, strip) if section.old is not None else None
    new = _strip(section.new, strip) if section.new is not None else None

    # Multiple header forms must agree. /dev/null represents the absent side.
    expected_old = rf or cf or d_old
    expected_new = rt or ct or d_new
    if old not in (None, b"/dev/null") and expected_old not in (None, old):
        raise DiffParseError("conflicting old paths across patch headers")
    if new not in (None, b"/dev/null") and expected_new not in (None, new):
        raise DiffParseError("conflicting new paths across patch headers")
    if section.new_mode and old not in (None, b"/dev/null"):
        raise DiffParseError("new file mode requires /dev/null old path")
    if section.deleted_mode and new not in (None, b"/dev/null"):
        raise DiffParseError("deleted file mode requires /dev/null new path")

    found = [p for p in (d_old, d_new, old, new, rf, rt, cf, ct) if p and p != b"/dev/null"]
    if not found:
        raise DiffParseError("file section has no target path")
    return found


def parse_diff(data: bytes, strip: int = 1) -> ParsedDiff:
    """Extract every affected repository path, rejecting ambiguous patches."""
    if not isinstance(data, bytes):
        raise TypeError("patch data must be bytes")
    if strip < 0:
        raise DiffParseError("strip must be non-negative")
    if len(data) > 64 * 1024 * 1024:
        raise DiffParseError("patch exceeds 64 MiB safety limit")
    if not data or b"\x00" in data:
        raise DiffParseError("patch is empty or contains NUL bytes")
    binary_markers = (b"GIT binary patch", b"Binary files ", b"literal ", b"delta ")
    if any(line.startswith(binary_markers) for line in data.splitlines()):
        raise DiffParseError("binary patches are unsupported")

    sections: List[_Section] = []
    current: Optional[_Section] = None
    pending_old: Optional[bytes] = None
    lines = data.splitlines()
    hunk_old = hunk_new = 0
    allow_no_newline_marker = False
    for line in lines:
        if hunk_old or hunk_new:
            if line == b"\\ No newline at end of file" and allow_no_newline_marker:
                allow_no_newline_marker = False
                continue
            if not line:
                raise DiffParseError("malformed empty line inside hunk")
            marker = line[:1]
            if marker == b" ":
                hunk_old -= 1
                hunk_new -= 1
            elif marker == b"-":
                hunk_old -= 1
            elif marker == b"+":
                hunk_new -= 1
            else:
                raise DiffParseError("malformed hunk body")
            if hunk_old < 0 or hunk_new < 0:
                raise DiffParseError("hunk contains more lines than declared")
            allow_no_newline_marker = True
            continue
        if line == b"\\ No newline at end of file" and allow_no_newline_marker:
            allow_no_newline_marker = False
            continue
        allow_no_newline_marker = False
        if line.startswith(b"@@ "):
            if current is None or current.old is None or current.new is None:
                raise DiffParseError("hunk without paired file headers")
            match = re.match(br"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$", line)
            if match is None:
                raise DiffParseError("malformed hunk header")
            try:
                hunk_old = int(match.group(2) or b"1")
                hunk_new = int(match.group(4) or b"1")
            except (ValueError, OverflowError):
                raise DiffParseError("hunk count is too large") from None
            if hunk_old == 0 and hunk_new == 0:
                raise DiffParseError("empty hunk is unsupported")
            current.hunks += 1
            continue
        if line.startswith(b"diff --git "):
            if pending_old is not None:
                raise DiffParseError("unpaired --- header")
            if current is not None:
                sections.append(current)
            current = _Section()
            current.diff_old, current.diff_new = _two_git_paths(line[11:])
        elif line.startswith(b"--- "):
            if pending_old is not None:
                raise DiffParseError("duplicate --- header")
            pending_old = _one_path(line[4:], timestamps=True)
            if current is None:
                current = _Section()
        elif line.startswith(b"+++ "):
            if pending_old is None or current is None:
                raise DiffParseError("+++ header without preceding ---")
            if current.old is not None:
                # A second traditional section without a diff --git delimiter.
                if current.diff_old is not None:
                    raise DiffParseError("duplicate ---/+++ headers in Git section")
                sections.append(current)
                current = _Section()
            current.old = pending_old
            current.new = _one_path(line[4:], timestamps=True)
            pending_old = None
        elif current is not None and line.startswith(b"rename from "):
            if current.rename_from is not None or current.old is not None:
                raise DiffParseError("duplicate or misplaced rename from header")
            current.rename_from = _one_path(line[12:])
        elif current is not None and line.startswith(b"rename to "):
            if current.rename_to is not None or current.old is not None:
                raise DiffParseError("duplicate or misplaced rename to header")
            current.rename_to = _one_path(line[10:])
        elif current is not None and line.startswith(b"copy from "):
            if current.copy_from is not None or current.old is not None:
                raise DiffParseError("duplicate or misplaced copy from header")
            current.copy_from = _one_path(line[10:])
        elif current is not None and line.startswith(b"copy to "):
            if current.copy_to is not None or current.old is not None:
                raise DiffParseError("duplicate or misplaced copy to header")
            current.copy_to = _one_path(line[8:])
        elif current is not None and line.startswith(b"new file mode "):
            if current.new_mode or current.old is not None:
                raise DiffParseError("duplicate or misplaced new file mode header")
            _validate_mode(line[14:], "new file mode")
            current.new_mode = True
        elif current is not None and line.startswith(b"deleted file mode "):
            if current.deleted_mode or current.old is not None:
                raise DiffParseError("duplicate or misplaced deleted file mode header")
            _validate_mode(line[18:], "deleted file mode")
            current.deleted_mode = True
        elif current is not None and line.startswith(b"old mode "):
            if current.old_mode is not None or current.old is not None:
                raise DiffParseError("duplicate or misplaced old mode header")
            current.old_mode = _validate_mode(line[9:], "old mode header")
        elif current is not None and line.startswith(b"new mode "):
            if current.changed_mode is not None or current.old is not None:
                raise DiffParseError("duplicate or misplaced new mode header")
            current.changed_mode = _validate_mode(line[9:], "new mode header")
        elif current is not None and line.startswith(b"index "):
            if current.index_seen or current.old is not None:
                raise DiffParseError("duplicate or misplaced index header")
            if re.fullmatch(br"[0-9a-fA-F]+\.\.[0-9a-fA-F]+(?: [0-7]{6})?", line[6:]) is None:
                raise DiffParseError("malformed index header")
            current.index_seen = True
            fields = line[6:].split(b" ")
            if len(fields) == 2:
                _validate_mode(fields[1], "index mode")
        elif current is not None and line.startswith((b"similarity index ", b"dissimilarity index ")):
            if current.old is not None:
                raise DiffParseError("misplaced similarity header")
            is_dissimilarity = line.startswith(b"dissimilarity index ")
            if ((is_dissimilarity and current.dissimilarity_seen)
                    or (not is_dissimilarity and current.similarity_seen)):
                raise DiffParseError("duplicate similarity header")
            value = line.split(b" ")[-1]
            if re.fullmatch(br"(?:100|[0-9]{1,2})%", value) is None:
                raise DiffParseError("malformed similarity header")
            if is_dissimilarity:
                current.dissimilarity_seen = True
            else:
                current.similarity_seen = True
        elif not line:
            continue
        else:
            raise DiffParseError("unsupported or misplaced patch line")

    if pending_old is not None:
        raise DiffParseError("unpaired --- header")
    if hunk_old or hunk_new:
        raise DiffParseError("truncated hunk body")
    if current is not None:
        sections.append(current)
    if not sections:
        raise DiffParseError("diff contains no file sections")

    raw_paths: List[bytes] = []
    for section in sections:
        raw_paths.extend(_finish(section, strip))
    paths = tuple(sorted({os.fsdecode(path) for path in raw_paths}))
    return ParsedDiff(paths=paths, file_count=len(sections))
