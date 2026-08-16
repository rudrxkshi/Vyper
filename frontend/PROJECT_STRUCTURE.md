# Suggested Frontend Structure

This is a recommended React dashboard structure for handoff.

```text
frontend/
  README.md
  API_CONTRACT.md
  PROJECT_STRUCTURE.md
  src/
    app/
      layout.tsx
      page.tsx
      dashboard/
      assets/
      jobs/
      certificates/
      audit-logs/
      settings/
    components/
      navigation/
      cards/
      tables/
      status-badges/
      json-viewer/
      forms/
    features/
      assets/
      jobs/
      certificates/
      audit-logs/
      settings/
    lib/
      api/
      types/
      utils/
    styles/
```

## Screen responsibilities

### Dashboard

- recent jobs
- current asset counts
- verified / failed / inconclusive summaries
- quick access to recent certificates

### Assets

- inventory table
- system-device warnings
- mount and device-type metadata
- read-only details panel

### Jobs

- create sanitization job
- display live status
- surface dry-run mode
- show the full pipeline state chain

### Job detail

- execution payload
- verification payload
- evidence payload
- certificate payload
- audit log entries related to the job

### Certificates

- certificate index
- certificate detail
- hash and claim display

### Audit logs

- request/response entries
- actor metadata
- timestamps

## Component notes

- Keep job state badges and final outcome badges separate.
- Show nested JSON in a collapsible viewer rather than raw text blobs.
- Treat assets as read-only inventory unless the backend explicitly exposes a safe action.
