# Contributing

Security reports belong in the private channel described in [SECURITY.md](SECURITY.md). For other
bugs, include a minimal synthetic patch and the exact JSON result.

## Ground rules

- Preserve the fail-closed parser: ambiguous or unsupported syntax must be rejected.
- Keep the runtime core standard-library-only.
- Add adversarial regression tests for every parser or path-safety change.
- Tests must not read or write outside their temporary directories.
- Git-dependent tests must skip cleanly when Git is unavailable.

Set up a development checkout with:

```bash
python -m pip install -e '.[dev]'
pytest -q
```

There is no Developer Certificate of Origin requirement.

## Support expectations

Maintenance is best-effort, with no SLA or commercial support.
