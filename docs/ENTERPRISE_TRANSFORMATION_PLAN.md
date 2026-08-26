# Enterprise transformation assessment and plan

## Assessment date and baseline

Assessment performed on 2026-08-26 against `main` at `35275c2` with a clean
working tree. VYPER is not a blank local wiping utility: it is an
evidence-oriented local sanitization product with a substantial central-control
prototype. The implementation should therefore evolve the existing contracts
instead of replacing the agent, sanitization pathways, or durable job model.

### Validation baseline

- `npm test` in `frontend/user-dashboard`: passed (26 tests).
- Python test suite was not executed in this environment because the available
  `python3` installation does not have `pytest`. No dependencies were installed
  during this audit.
- The production configuration uses PostgreSQL and Alembic; the local demo path
  retains SQLite compatibility. Existing data must be migrated, never reset.

## Existing architecture and reusable components

| Area | Current implementation | Reuse decision |
| --- | --- | --- |
| Local sanitization | `agent/` provides profiling, policy selection, HDD/ATA/NVMe pathways, verifier, evidence, and certificates. `local_agent/` provides durable job orchestration and the loopback API. | Preserve as the endpoint data plane and extend only at authorization boundaries. |
| Privilege boundary | The package runs an unprivileged agent and a fixed-function root executor over a group-restricted Unix socket. It has no generic remote shell. | Preserve; command handling must call the existing typed job pathway only. |
| Offline execution | `LocalJobStore` persists jobs, remote requests, sequenced events, and an outbox. Restart recovery fails closed to `INCONCLUSIVE`; sync is outbound polling. | Reuse as the offline queue and extend it for signed-command receipts and replay state. |
| Enrollment and agent inventory | One-use expiring enrollment tokens, hashed bearer agent credentials, inventory synchronization, and agent records already exist. An Ed25519 identity store and backend identity fields also exist. | Complete the currently disconnected identity flow; do not introduce permanent installer API keys. |
| Remote requests | Central jobs are targeted to an enrolled agent's synchronized hardware identity, expire, are idempotent, and require central plus local approval for destructive work. | Evolve into the signed command state machine. |
| Command cryptography | Backend has Ed25519 signing; local code has signature and expiration verification helpers. | Wire these into enrollment, assignment, durable nonce consumption, and failure events. |
| Central security | Password sessions, RBAC, TOTP/recovery-code MFA, CSRF, audit-chain records, result integrity quarantine, and basic security events are implemented. | Extend roles, tenant scope, approvals, and audit semantics rather than replace auth in-place. |
| UI | Next.js dashboard already shows assets, local/central jobs, certificates, audit logs, remote agents, and remote job approval. | Extend the present dashboard contract and screens; read `frontend/user-dashboard/AGENTS.md` before modifying it. |
| Delivery | Docker production compose, Alembic migrations, a Linux installer, systemd units, release/SBOM tooling, and deployment documentation exist. | Keep the package format and add deployment components only when a vertical slice needs them. |

## Important current behavior

The central service never opens an inbound connection to an endpoint. An agent
polls over outbound HTTPS, synchronizes inventory and heartbeats through its
durable outbox, then uploads sequenced lifecycle events and a terminal result.
The backend accepts `VERIFIED` only when endpoint verification, evidence hash,
and certificate consistency checks agree. Destructive central requests stop at
local approval, after fresh target discovery and stable hardware-identity
checks. These are security invariants to retain.

## Gaps relative to the enterprise target

1. **Enrollment identity is incomplete.** `Ed25519IdentityStore` exists, and
   backend schemas/records can hold a public key, but `CentralSyncClient.enroll`
   does not currently generate/send the device key and identity fingerprint.
2. **Signed commands are not yet enforced end-to-end.** Signing and verifier
   helpers exist, but `/agent/jobs/next` returns an unsigned job assignment and
   the sync client stores/approves it without calling the verifier. The stored
   nonce is not a consumed, replay-protected signed-command receipt.
3. **Organization tenancy is absent.** Current users, agents, assets, tokens,
   jobs, and events are globally scoped. Organization IDs and data isolation
   must arrive in an additive migration before multi-tenant operation.
4. **Approval workflow is only a boolean authorization.** MFA/RBAC are present,
   but there are no immutable approval entities, separate approvers, two-person
   rules, or policy-driven authorization states.
5. **Policy is endpoint-centric.** The existing policy engine selects safe
   storage methods; it does not yet consume centrally managed remote-operation
   policy or device-category restrictions.
6. **Security events and tamper checks are partial.** Events exist for some
   enrollment/result paths, but there is no complete event taxonomy, endpoint
   tamper monitor, identity-change review state, or deterministic risk score.
7. **Evidence storage remains database JSON.** It is sound for current payloads
   but has no object-storage reference/bundle model for enterprise evidence.
8. **Dashboard coverage is operational rather than enterprise-complete.** It
   lacks first-class policy, approval, event, risk, device-detail, and evidence
   views. Existing job status is polling-based, not websocket-driven.
9. **Documentation exists but is release-focused.** The required control-plane
   security architecture, remote-sanitization API, enterprise deployment, and
   explicit trust-boundary documentation need consolidated updates.

## Compatibility-preserving delivery plan

### Slice 1 — signed identity and remote command enforcement

Add an additive migration and protocol version negotiation for agent public
identity, trusted central signing key pinning, canonical signed command
envelopes, and durable nonce receipt/consumption. Enrollment must generate the
Ed25519 key locally; the private key never leaves the endpoint. The agent will
verify signature, key ID, intended agent, operation allowlist, expiry, nonce,
authorization, policy, target identity, and safety state before submitting the
existing local job. Every rejection creates a local record and a synchronized
security event. Preserve the existing local approval requirement for destructive
work.

Acceptance tests: enrollment identity, valid/invalid signature, expired,
wrong-device, replayed, unauthorized, changed-target, and offline authorized
execution/recovery.

### Slice 2 — organization, policy, approval, and audit model

Introduce organizations, organization membership/roles, policy records,
approvals, and an organization-scoped audit/security-event model through
additive Alembic migrations. Map existing ADMIN/OPERATOR/AUDITOR behavior
compatibly, then add SUPER_ADMIN, SECURITY_ADMIN, and VIEWER. Implement a
request → policy evaluation → approval(s) → signed command lifecycle. Approval
records must be append-only and a requester cannot satisfy an independent
second-approval requirement.

Acceptance tests: tenant isolation, policy block, role block, MFA requirement,
single/two-person approval, expiry before approval, and immutable audit events.

### Slice 3 — endpoint posture, security events, and risk

Add a small endpoint tamper/posture component that hashes approved configuration
and records key, identity, and storage-inventory changes. Fail closed for a
destructive command when an identity or safety mismatch is unresolved. Add a
deterministic, versioned risk calculator whose stored factors explain each
score; it must not use AI or undisclosed heuristics.

Acceptance tests: configuration/key changes, storage change, mismatch block,
event synchronization, and stable risk-score explanations.

### Slice 4 — evidence, API, and dashboard

Add an evidence-bundle abstraction with metadata/hash/certificate linkage in
PostgreSQL and an S3-compatible object-store adapter. Keep small legacy JSON
payloads readable. Add versioned enterprise API endpoints and extend the
existing dashboard with device detail, risk, approval, event, policy, evidence,
certificate, and job-lifecycle views. Use real state transitions only; do not
invent progress. Websocket notifications may be added only after the REST state
model is complete and tested.

Acceptance tests: evidence retry/synchronization, object references, no
fabricated certificate, and UI contract tests for each state.

### Slice 5 — deployment and production hardening

Expand Compose/documentation for Redis, MinIO, and optional external OIDC
integration; keep PostgreSQL mandatory in production. Provide configuration and
installer upgrades without exposed inbound ports or hardcoded credentials.
Document secret management, TLS, backups, monitoring, upgrades, uninstall,
incident handling, and explicit trust boundaries. Validate with mocked devices,
loop devices, or disposable VMs only.

## Non-negotiable invariants

- No generic remote shell, arbitrary argv, or backend block-device access.
- Central issuance is never evidence of successful sanitization.
- Only the local agent executes and verifies a sanitization job.
- An expired, replayed, unsigned, wrong-device, unapproved, policy-blocked, or
  identity-mismatched destructive command fails closed.
- Active system disks, mounted/ambiguous targets, and uncertain device state
  remain blocked by the existing local safeguards.
- Offline authorized work and evidence remain durable; reconnection only
  synchronizes state and evidence.
- Existing API/version behavior and historical data remain readable during the
  migration path.

## Immediate next implementation task

Slice 1 is implemented in the current working tree: enrollment binds the
endpoint's locally generated Ed25519 public key, job assignments are signed,
and the agent verifies and durably receipts a command before it can reach local
approval. The added regression coverage covers identity binding, invalid key
identity, signed delivery, and conflicting nonce reuse. Full Python execution
remains pending installation of the pinned test dependencies.

Slice 2 is now started as a working backend vertical slice. It adds
organizations, organization-bound enrollment tokens/agents, remote policy
records, append-only central-job approvals, and an `AWAITING_APPROVAL` state.
Policy-backed destructive requests remain undeliverable until the configured
number of distinct security administrators has approved; approvers cannot
approve their own request, and a real session must carry MFA assurance. The
legacy no-policy path remains compatible while organizations are migrated.

The next task is to complete tenant isolation for every read/write endpoint and
add policy administration and approval views to the dashboard. This must keep
the local approval gate independent of all central approval counts.
