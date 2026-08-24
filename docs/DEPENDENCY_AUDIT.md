# Dependency security audit

Audit date: 2026-08-25

- Python: `pip-audit -r requirements.lock -r requirements-central.lock` — no known vulnerabilities found.
- Frontend: `npm audit --audit-level=high` against `package-lock.json` — 0 vulnerabilities.
- No automatic dependency upgrade was applied. Runtime, central, build, and audit-tool versions are pinned in `requirements.lock`, `requirements-central.lock`, `pyproject.toml`, and `package-lock.json`.

CI repeats both audits on pull requests. Advisory databases change over time, so this report is a point-in-time result rather than a guarantee.
