# diff-gate

[![CI](https://github.com/gexiro-global/diff-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/gexiro-global/diff-gate/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/diff-gate.svg)](https://pypi.org/project/diff-gate/)
[![Python](https://img.shields.io/pypi/pyversions/diff-gate.svg)](https://pypi.org/project/diff-gate/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Preflight untrusted unified diffs against explicit path policy before Git can change your workspace.

`diff-gate` strictly parses textual Git/unified patches, reports every affected path, applies
allow/deny globs, rejects traversal and symlink paths, and delegates patch validation and atomic
application to `git apply`. The core has no third-party runtime dependencies.

## Install

```bash
pip install diff-gate
```

Python 3.9 or newer is required. `inspect` needs only Python; `check` and `apply` require Git, and
`--root` must be the Git work-tree root (not a subdirectory).

## Quick start

```bash
diff-gate inspect change.patch --root /workspace/project
diff-gate check change.patch --root /workspace/project --deny '.env' --deny 'secrets/**'
diff-gate apply change.patch --root /workspace/project --allow 'src/**' --allow 'tests/**'
```

JSON is the deterministic default. Add `--format text` for a human-readable report. Use `-` as the
patch name to read bytes from standard input. A named patch file must be a regular, non-symlinked
file inside `--root`; use standard input when the patch is stored elsewhere. Patch input is capped
at 64 MiB and individual pathnames at 4096 decoded bytes.

Exit codes are `0` for safe or applied, `1` for a safety/policy/Git-check rejection, and `2` for
bad usage, unreadable input, or malformed/unsupported patch syntax.

## Threat model

`diff-gate` is designed to stop an untrusted textual patch from naming a path outside the selected
workspace, traversing an existing symbolic link, or touching a path excluded by caller policy. It
decodes Git's C-quoted paths, cross-checks redundant Git headers, rejects ambiguous headers,
binary patches, and symlink-mode changes, and runs the exact patch through `git apply --check`
before application. Patch bytes are passed directly to Git without a shell.

It is **not a sandbox**. It gates destinations, not the semantic meaning of source code: an allowed
patch can add malicious code, change a build script, or create a hard link through application
behavior outside this tool. Git hooks or later builds are outside its scope. A hostile concurrent
process that can modify the workspace can race the path checks; checks are repeated immediately
before Git, but portable Python plus a `git` subprocess cannot make the pathname validation and
Git's writes one indivisible filesystem operation. Run it in an isolated workspace whose parent,
Git executable, Git configuration, and environment are trusted. Resource exhaustion by very large
patches is also out of scope.

The guarantee therefore applies only when the gate is the sole actor changing an isolated
workspace during a run. In particular, it is not an OS security boundary and does not defend a
shared workspace against a concurrent hostile process.

## Modes

- `inspect` parses paths and evaluates policy only. It never invokes Git or writes files.
- `check` additionally requires a Git work tree and runs `git apply --check`.
- `apply` runs both gates, refuses a dirty tree by default, repeats path validation, then invokes
  `git apply`. Git applies a patch transactionally; a failed apply is not accepted as success.

`--allow-dirty` relaxes only the clean-tree gate. It does not relax parsing, path, policy, or Git
preflight checks.

## Policy

The default allow list is `**` and the default deny list is empty. Repeat `--allow` or `--deny` to
provide multiple case-sensitive POSIX-style globs. Deny always wins. Paths are evaluated after
`--strip N` normalization; the default `--strip 1` maps conventional `a/file` and `b/file` headers
to `file`. Rename and copy source and destination paths are all gated.

Examples:

```bash
diff-gate inspect update.patch --allow 'src/**' --allow 'tests/**' \
  --deny 'src/generated/**' --deny '**/*.pem'
```

Existing symlink components are rejected even when they currently point inside the root. Patches
that create or modify symlinks (`120000` mode) and binary Git patches are deliberately unsupported.
Non-canonical symlink modes with the same file-type bits, Gitlinks, other non-regular modes,
reserved `.git` components, Windows device names, drive paths, alternate streams, and components
with trailing dots or spaces are rejected as well.

## Python API

```python
from pathlib import Path
from diff_gate import run_gate

result = run_gate(
    Path("change.patch").read_bytes(),
    mode="check",
    root=Path("/workspace/project"),
    allow=("src/**", "tests/**"),
    deny=("**/*.pem",),
)
print(result.as_dict())
```

## Development

```bash
python -m pip install -e '.[dev]'
pytest -q
```

## License

Apache-2.0. See [LICENSE](LICENSE).

Built and maintained by [Gexiro Global Enterprises Ltd](https://gexiro.com).

Part of the [Gexiro open-source toolkit](https://github.com/gexiro-global).
