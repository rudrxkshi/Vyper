# VYPER handover

## Current date/time

2026-08-26, Asia/Kolkata.

## Current branch

`main` tracking `origin/main`; baseline commit is `35275c2` (`stiff`).

## Project state

VYPER remains an evidence-driven local sanitization platform with an outbound
central control plane. The existing profiler, policy engine, pathways, verifier,
evidence, certificates, fixed-function privileged executor, durable SQLite
local jobs/outbox, and Linux packaging were preserved.

Two incremental enterprise-control-plane slices are present in the working tree:

1. Endpoint-bound Ed25519 enrollment and signed remote command validation.
2. Initial organization/policy/approval backend workflow.

The worktree is intentionally uncommitted. Do not discard these changes.

## What was completed

### Secure endpoint identity and remote commands

- Agent enrollment creates an endpoint-local Ed25519 key using
  `local_agent.identity.Ed25519IdentityStore`.
- The private key is written with mode `0600`; enrollment sends only public PEM,
  public-key ID, and a privacy-preserving endpoint fingerprint.
- The central service validates that the submitted key is an Ed25519 PEM and
  that its SHA-256 key ID matches before registering the agent.
- Central job delivery now persists and returns a canonical signed `SANITIZE`
  command. It includes command/job ID, target agent, issue/expiry timestamps,
  nonce, typed parameters, and authorization metadata.
- The local agent pins the central verification key supplied at enrollment and
  verifies command signature, key ID, agent target, operation allowlist,
  issue/expiry timestamps, and parameters before writing a remote request.
- `LocalJobStore.remote_command_receipts` durably detects nonce/command-ID reuse
  with a different command. Identical transport retries are safe/idempotent.
- The pre-existing re-discovery, stable target identity, mounted/system-disk,
  eligibility, separate local approval, and durable worker safeguards remain in
  force before an actual sanitization job is submitted.

### Initial organization, policy, and approval workflow

- Added organization records and organization-scoped remote policy records.
- Enrollment tokens may carry an organization ID; enrolled agents inherit it.
- Policies can allow/block remote sanitization, disallow system-disk use, and
  require zero to two central approvals.
- Policy-backed destructive requests enter `AWAITING_APPROVAL`; they cannot be
  claimed/delivered until the required number of approvals is reached.
- Central approvals are append-only, one per real user per job, and prevent a
  requester from approving their own job.
- Approval is limited to `SUPER_ADMIN`, `ADMIN`, or `SECURITY_ADMIN`, and a
  non-development session must have TOTP or recovery-code MFA assurance.
- The existing local approval remains independent and is still required for
  destructive execution.
- Legacy jobs with no policy retain their existing behavior during migration.

## Files changed

- `README.md`: documents local key generation, central-key pinning, command
  validation, and local approval behavior.
- `VYPER_ARCHITECTURE.md`: documents the signed-command/receipt trust boundary.
- `docs/ENTERPRISE_TRANSFORMATION_PLAN.md`: architecture assessment, completed
  slices, gaps, and ordered future work.
- `local_agent/identity.py`: Ed25519 identity store and endpoint fingerprint.
- `local_agent/command_verifier.py`: validates command ID, issued timestamp,
  required parameters, expiry, target, operation, key ID, and Ed25519 signature.
- `local_agent/storage.py`: `remote_command_receipts` and replay exception.
- `local_agent/sync.py`: identity-bearing enrollment, central verification-key
  pinning, signed-command verification/receipt before persistence.
- `local_agent/main.py`: configures a durable identity-key path via
  `VYPER_AGENT_IDENTITY_PATH` (otherwise alongside credentials).
- `backend/app/routers/agents.py`: central command creation/delivery, identity
  validation, organization/policy endpoints, approval state machine.
- `backend/app/models.py`: organization, remote-policy, central-job-approval,
  and additive organization/policy/approval fields.
- `backend/app/schemas.py`: organization, policy, and policy-ID request models.
- `backend/app/auth.py`: adds SUPER_ADMIN, SECURITY_ADMIN, and VIEWER roles.
- `backend/app/routers/auth.py`, `audit_logs.py`, `security_events.py`: allows
  appropriate new admin/read-only roles.
- `backend/app/main.py`: production schema head now requires migration 0004.
- `migrations/versions/0004_organization_policy_approvals.py`: forward-only
  additive migration.
- `tests/test_stage4_sync.py`: identity, signed delivery/replay, and approval
  workflow regression cases.

## Database changes

Migration head is now `0004_organization_policy_approvals`.

- New tables: `organizations`, `remote_policies`, `central_job_approvals`.
- New nullable compatibility columns: `agents.organization_id`,
  `agent_enrollment_tokens.organization_id`, `central_jobs.organization_id`,
  `central_jobs.policy_id`, and `central_jobs.required_approvals`.
- Existing records remain readable. A later migration should backfill an
  explicitly chosen default organization only after product/upgrade policy is
  decided; do not silently invent tenant ownership for production data.
- The 0004 migration is forward-only. Take a tested backup before applying it.

## API changes

New central endpoints:

- `POST /organizations` — create organization (SUPER_ADMIN/ADMIN).
- `POST /organizations/{organization_id}/policies` — create remote policy
  (security admin role).
- `GET /organizations/{organization_id}/policies` — list policies.
- `POST /central-jobs/{central_job_id}/approvals` — add a security approval.

Changed contracts:

- `POST /agents/enrollment-tokens` accepts optional `organization_id`.
- `POST /agents/{agent_id}/jobs` accepts optional `policy_id`.
- `GET /agent/jobs/next` includes `command`, a signed canonical command
  envelope. A new agent must reject an assignment without this envelope.
- Central job read records now include organization/policy/approval fields.

## Agent changes

- Add `VYPER_AGENT_IDENTITY_PATH` to deployment/installer configuration when
  the desired key location is `/etc/vyper`; default is an `agent_identity.pem`
  sibling of the credential file.
- Credentials now include central command verification PEM/key ID. Do not print,
  log, or place them in browser storage.
- `CentralSyncClient.poll_job()` must be the only path that accepts remote
  central jobs. It validates the signed command before `save_remote_request`.
- Existing direct local jobs and boot handoff remain separate workflows.

## Security decisions that must not be reversed

- Never add arbitrary remote shell, executable, argv, or shell-fragment fields.
- The central service cannot claim a wipe succeeded merely because it issued a
  job; only verified agent evidence/certificate state can do that.
- Do not bypass signature, target-agent, expiry, nonce, target identity, local
  approval, or existing mounted/system-device safety validation.
- Preserve outbound-only endpoint communication. Do not expose the local API to
  the public internet.
- Do not treat an offline device or disconnected result as verified.
- Keep approval records append-only; do not turn an approval into a mutable
  boolean flag.
- Do not make central approvals replace fresh local authorization.

## Tests and validation

Passed:

- `npm test` in `frontend/user-dashboard`: 26/26 dashboard contract tests.
- AST syntax checks for the modified Python files.
- `git diff --check`.

Not run:

- `python3 -m pytest tests -q` cannot run in the current environment because
  its Python interpreter has neither `pytest` nor the pinned runtime modules
  (including `cryptography`). No packages were installed automatically.

After a developer-approved dependency setup, run:

```bash
python3 -m pip install -r requirements.lock pytest
python3 -m pytest tests -q
(cd frontend/user-dashboard && npm test && npm run lint && npm run build)
```

If installing needs network or changes a shared Python environment, use a
project-local virtual environment and obtain approval first.

## Known issues and next steps

1. **Complete tenant isolation.** Organization IDs are carried through new
   enrollment/job/policy paths, but all existing list/read/update endpoints are
   not yet universally filtered by organization membership. Introduce explicit
   organization membership/role records and make every central query scoped.
2. **Finish policy lifecycle.** Add update/revoke/versioning, policy selection
   defaults, device-category rules, verification-inconclusive disposition, and
   a clear policy-evaluation record in command/evidence metadata.
3. **Improve approval workflow.** Add explicit request/reject/cancel states,
   expiry while awaiting approval, separate requester/approver identity in
   development fixtures, two-person approval regression tests using real users,
   and security-event records for request/approval/rejection/policy blocks.
4. **Add endpoint security events.** Create an authenticated, typed outbound
   endpoint event upload path for invalid signature, expiry, replay, identity
   mismatch, storage change, and tamper events. Persist/retry it through the
   outbox; never upload secrets.
5. **Tamper and risk slice.** Implement a small configuration/key/inventory
   tamper monitor and deterministic explainable risk factors. Fail closed for
   unresolved identity anomalies.
6. **Evidence/object storage.** Add S3-compatible object-storage metadata and
   evidence-bundle upload/retry while retaining legacy JSON readability.
7. **Dashboard.** Before editing `frontend/user-dashboard`, read its
   `AGENTS.md`. Add device detail, policy, approval, security event, risk,
   evidence, and certificate views using the real backend states only.
8. **Docs/deployment.** Add the requested `SECURITY_ARCHITECTURE.md`,
   `DEPLOYMENT.md`, `AGENT_INSTALLATION.md`, `REMOTE_SANITIZATION.md`, and
   `API.md`; add Redis/MinIO/OIDC only when the vertical slice requires them.
9. **Review migration 0004 on PostgreSQL and SQLite.** In particular, add
   database-level foreign-key constraints/indexes for additive organization
   columns where supported, and write a tested backfill procedure instead of
   inferring tenant ownership.
10. **Run full tests** in a dependency-equipped environment before claiming
    production readiness.

## Useful commands

```bash
# Central development API
uvicorn backend.app.main:app --reload

# Local agent (Linux runtime)
python3 -m local_agent.main

# Test suites
python3 -m pytest tests -q
(cd frontend/user-dashboard && npm test)

# Production migration and containers
alembic upgrade head
docker compose -f docker-compose.production.yml up --build

# Build Linux release
python3 packaging/build_release.py
```

## Git status

Modified tracked files and new files are listed in the `Files changed` section.
At handover creation, the worktree includes those intentional uncommitted
changes only. Re-check with `git status --short --branch` before editing.

## Safety notes

VYPER can invoke destructive HDD overwrite, ATA secure erase, and NVMe sanitize
through its existing typed local executor. Do not target a developer system disk
or a mounted/ambiguous device. Automated destructive tests must use mocks,
fixtures, loopback devices, or a disposable VM. Physical-hardware operations
remain operator-gated and are documented under `docs/PHYSICAL_*`.
