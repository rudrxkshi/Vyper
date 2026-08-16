# Vyper

## Backend Demo

The backend API lives under `backend/app/` and now follows the dashboard flow shown in the architecture diagram: React dashboard → FastAPI backend → PostgreSQL → secure agent API → Linux sanitization agent.

It stores assets, jobs, results, certificates, and audit logs.

PostgreSQL is used when `VYPER_DATABASE_URL` or the `VYPER_POSTGRES_*` variables are set; otherwise the local demo fallback is SQLite.

Run it with:

```bash
uvicorn backend.app.main:app --reload
```

Core routes:

- `GET /assets`
- `GET /devices`
- `POST /jobs/sanitize`
- `GET /jobs`
- `GET /results`
- `GET /certificates`
- `GET /audit-logs`
- `GET /health`
