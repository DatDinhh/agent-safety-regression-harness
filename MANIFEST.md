# ASRH Clean Distribution Manifest

This archive contains the clean project source and reproducible artifacts for ASRH.

Included:

- top-level project files: `README.md`, `pyproject.toml`, `Makefile`, `.gitignore`, `.env.example`
- source package: `asrh/`
- 50 YAML cases: `suites/`
- canonical sample traces: `runs/sample_baseline.jsonl`, `runs/sample_guarded.jsonl`
- canonical sample reports: `reports/sample_baseline.md`, `reports/sample_guarded.md`, `reports/sample_comparison.md`
- tests: `tests/`
- documentation: `docs/`
- paper outline: `paper/outline.md`

Intentionally excluded:

- `.venv/`
- `.pytest_cache/`
- `__pycache__/`
- `_backups/`
- `.git/`
- generated local debug runs not intended as canonical samples

A virtual environment must be recreated locally after extraction.
