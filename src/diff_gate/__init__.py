"""Safely inspect and apply policy-gated unified diffs."""

from .gate import GateResult, run_gate
from .parser import DiffParseError, ParsedDiff, parse_diff

__all__ = ["DiffParseError", "GateResult", "ParsedDiff", "parse_diff", "run_gate"]
__version__ = "0.1.0"
