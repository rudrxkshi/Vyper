# Frozen protocol and schema versions

| Interface | Version | Compatibility rule |
|---|---:|---|
| Local HTTP API | 2 | Clients must use major v2; another major is rejected. |
| Central/local agent protocol | 1 | Every sync request/response carries v1; mismatch is rejected before work. |
| Privileged executor protocol | 1 | Typed Unix-socket messages with another version are rejected. |
| Boot manifest schema | 1 | Unknown schema, replay, expiry, signature, identity, or mode fails closed. |
| Evidence structural schema | 1 | Current `EvidenceRecord` shape and canonical SHA-256 payload; additions require compatibility review. |
| Certificate schema | 1.0.0 | Unknown major versions are not accepted as VYPER 1 certificates. |
| Local job-store schema | 2 | Initialized and recorded in `schema_metadata`. |
| Central database | Alembic `0009_merge_migration_heads` | Production must be at the single merged head; `create_all` is development/test-only. |

Minor additive evolution may be accepted only where the parser explicitly tolerates it. Major-version mismatch never falls back to a different sanitization method or execution mode.
