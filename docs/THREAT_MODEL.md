# VYPER threat model

## Scope and assets

Protected assets are disk data, operator accounts and sessions, agent and enrollment credentials, the central database, evidence and certificates, and release artifacts. System-disk boot sanitization and non-Linux installers are out of scope.

## Trust boundaries and threats

The browser is untrusted. It can request only typed central or loopback-local API operations and can never submit shell commands. Central is a coordinator: it cannot open local block devices, and a destructive request requires both an authenticated ADMIN/OPERATOR decision and a separate local approval. Agents initiate outbound HTTPS sync, authenticate with revocable hashed bearer credentials, validate job ownership/expiry, re-discover the target, and compare durable device identity before execution.

Threats include malicious operators, compromised central/local hosts, replayed jobs/events, forged uploads, device/path swaps, local privilege escalation, MITM, stolen agent tokens, altered releases, firmware defects, and incorrect VERIFIED claims. Mitigations include RBAC, expiring stored sessions, rate limiting, idempotency/sequence constraints, TLS, local approval, target locks, process isolation, evidence/certificate hash validation, conservative crash recovery, checksum verification, optional detached signing hooks, structured redacted logs, and append-only hash-chained audit records.

## Residual risk

Application-level audit chaining is tamper-evident, not tamper-proof against a database administrator. Checksum-only releases do not establish publisher identity; signed releases require a trusted, non-revoked Ed25519 public-key identity. The root executor has a narrow typed Unix-socket interface, but compromise of that helper still grants storage access. TOTP reduces password-only account compromise but does not protect a fully compromised operator endpoint. Firmware may lie or fail unpredictably. PostgreSQL backups and signing keys require external secret-management and access-control processes.
