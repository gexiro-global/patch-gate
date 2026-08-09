# Security Policy

## Supported Versions

`diff-gate` v0.x is maintained on the latest v0.x release line.

## Reporting a Vulnerability

Use GitHub private vulnerability reporting if enabled on this repository, otherwise email
`admin@gexiro.com`. Do not open a public issue for a suspected path escape, parser discrepancy,
TOCTOU weakness, or partial-application problem.

Include the `diff-gate`, Python, Git, and operating-system versions, plus a minimal synthetic patch
and filesystem layout. Do not include credentials or proprietary source.

## Security boundaries

This tool assumes the workspace and its parent are not being concurrently modified by an attacker,
and that `git` from `PATH`, Git configuration, and the process environment are trusted. It rejects
all existing symlink path components and symlink-mode patches, then rechecks immediately before
application. This narrows but cannot eliminate the race between portable Python checks and a
separate Git process. Use an OS sandbox or isolated CI workspace when adversarial concurrency is in
scope.
