# Frontend Handoff

This folder is reserved for the React dashboard that sits in front of the VYPER backend.

## Purpose

The frontend is the operator-facing UI for:

- asset inventory
- job submission and monitoring
- certificate review
- audit log inspection

## Backend integration

The current backend exposes these routes:

- `GET /health`
- `GET /assets`
- `GET /devices`
- `POST /jobs/sanitize`
- `GET /jobs`
- `GET /results`
- `GET /certificates`
- `GET /audit-logs`

Recommended request header when backend authentication is enabled:

- `X-VYPER-API-Key: <key>`

## Environment variables

Suggested frontend environment variables:

- `NEXT_PUBLIC_VYPER_API_BASE_URL` - browser-visible base URL for the FastAPI backend

The optional API key and runtime API URL override are entered in Settings and
stored in browser local storage. Do not expose a server-side secret through a
`NEXT_PUBLIC_*` environment variable.

## Suggested routes / screens

- `/dashboard` - overview and recent activity
- `/assets` - inventory of devices/assets
- `/jobs` - job creation and job monitoring
- `/jobs/:jobId` - job detail, result, verification, and evidence
- `/certificates` - certificate list and certificate detail
- `/audit-logs` - audit trail viewer
- `/settings` - API base URL and optional auth settings

## Implementation notes

- Treat execution success as non-final until verification and certificate data are available.
- The UI should display the full state chain: profiling -> policy -> execution -> verification -> evidence -> certificate.
- Show dry-run mode clearly on every job screen.
- Never present a VERIFIED status without the backend-provided verification payload.
- Prefer read-only views for assets, results, certificates, and audit logs.
