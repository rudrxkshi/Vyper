# Frontend API Contract

This document is the handoff contract between the React frontend and the FastAPI backend.

## Authentication

If the backend enables API key enforcement, include:

- Header: `X-VYPER-API-Key`
- Value: the configured `VYPER_API_KEY`

## Base URL

The frontend should read the backend base URL from `VYPER_API_BASE_URL`.

## Job submission

### `POST /jobs/sanitize`

Request body:

```json
{
  "target": "/dev/sdb",
  "authorization": {
    "approved": true,
    "ata_password": "optional"
  },
  "dry_run": false
}
```

Important behavior:

- `dry_run: true` must be treated as non-destructive planning.
- `authorization.approved` must be explicit for destructive operations.
- `ata_password` only applies to ATA secure erase flows.

## Read models

### Assets

`GET /assets` and `GET /devices` return the same storage inventory view.

Useful fields:

- `id`
- `asset_type`
- `device_path`
- `device_type`
- `model`
- `serial_number`
- `is_system_device`
- `mounted`
- `mounted_partitions`
- `profile_json`

### Jobs

`GET /jobs` returns job records with nested asset, result, certificate, and audit log data.

Fields to surface in the UI:

- `job_state`
- `final_status`
- `pathway`
- `outcome_kind`
- `successful_sanitization_claim`
- `dry_run`
- `message`
- `state_history_json`
- nested `asset`
- nested `result`
- nested `certificate`
- nested `audit_logs`

### Results

`GET /results` returns execution, verification, and evidence payloads.

Useful fields:

- `job_id`
- `started_at`
- `completed_at`
- `duration_seconds`
- `execution_json`
- `verification_json`
- `evidence_json`

### Certificates

`GET /certificates` returns certificate metadata and certificate JSON.

Useful fields:

- `certificate_id`
- `job_id`
- `target`
- `final_status`
- `outcome_kind`
- `successful_sanitization_claim`
- `certificate_hash`
- `certificate_json`

### Audit logs

`GET /audit-logs` returns request/response audit entries.

Useful fields:

- `action`
- `actor`
- `request_json`
- `response_json`
- `created_at`

## UI states

The frontend should handle these job states explicitly:

- `PENDING`
- `PROFILING`
- `POLICY_SELECTED`
- `AWAITING_AUTHORIZATION`
- `RUNNING`
- `VERIFYING`
- `VERIFIED`
- `FAILED`
- `INCONCLUSIVE`
- `UNSUPPORTED`
- `CANCELLED`

## Rendering guidance

- Show destructive actions behind a clear confirmation step.
- Prefer status badges for job state and final status.
- Render certificate and audit payloads in expandable JSON panels.
- Highlight system-associated assets as blocked from destructive actions.
- Separate `job_state` from `final_status` in the UI; they are related but not identical.
