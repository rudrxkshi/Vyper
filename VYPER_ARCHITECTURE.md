# VYPER Architecture

## Local and central service boundaries

Remote/central management:

```text
Next.js Dashboard
        |
Central FastAPI
        |
Central Database
```

Local-machine execution:

```text
Local Dashboard/Client
        |
Local Agent API (127.0.0.1)
        |
VYPERAgent
        |
Block Device
```

Stage 4 adds an outbound-only synchronization protocol. The central service
never opens a connection to a local agent and does not require inbound NAT or
firewall rules:

```text
Central Dashboard -> Central API -> Central DB
                         ^
                         | HTTPS poll/upload (agent protocol v1)
                         |
Local Console -> Local Agent -> VYPERAgent -> Block Device
                    |
                    +-> SQLite jobs, remote requests, and durable outbox
```

The browser/local UI is unprivileged. The local agent is the privileged trust
boundary and exposes only typed health, discovery, and sanitization-job routes;
it does not expose arbitrary command execution. The central backend should not
require raw block-device access in the final architecture.

`LocalAgentGateway` is the current in-process development adapter.
`RemoteLocalAgentGateway` speaks the versioned local-agent HTTP contract. It
checks the service identity before dispatch and refuses a configured central URL
to prevent forwarding recursion.

## Inventory semantics

- Central `GET /assets`: persisted inventory/history.
- Central `GET /devices`: backward-compatible alias for persisted assets, not
  live discovery. Responses include `X-VYPER-Inventory-Source: persisted-assets`.
- Local agent `GET /devices`: live, read-only discovery on its own machine.

Discovery uses structured `lsblk --json` output and the existing
`DeviceProfiler`. It lists supported whole-disk candidates, excludes partitions
and obvious pseudo devices, retains system disks with a protection flag, reports
mounted child partitions, and treats profiling failures or unknown state as
ineligible rather than safe.

## Local job lifecycle

```text
UI
 |
POST /jobs/sanitize
 |
202 Accepted + local job id
 |
Controlled local worker
 |
VYPERAgent
 |
SQLite state + immutable sequenced events
 |
GET /jobs/{id}
 |
UI polling
```

The local transport is API version 2. Submission durably inserts `PENDING`
before dispatch and returns without waiting for sanitization. SQLite schema
version 1 stores timestamps, sanitized authorization metadata, orchestration
sections, terminal evidence, errors, progress, and append-only event history.
Plaintext ATA passwords remain only in the worker invocation and are cleared
after it finishes.

Destructive jobs use a persisted partial unique index over normalized targets,
so the same physical target cannot have two active destructive jobs. Dry runs
are excluded from this destructive lock. Terminal completion or worker failure
releases the index naturally; restart recovery prevents stale active rows.

On startup, completed jobs remain unchanged. A `PENDING` job that lost its
transient secrets is cancelled rather than guessed or resumed. Jobs interrupted
during profiling, policy selection, execution, or verification become
`INCONCLUSIVE` with the event: "Local agent restarted before terminal
verification could be confirmed." Recovery never creates a `VERIFIED` claim.

HDD progress is persisted only from the pathway's measured bytes-written
callback. ATA and NVMe firmware operations remain indeterminate unless their
actual protocol status exposes trustworthy measurements. No timer-derived
percentage is generated.

Cancellation is supported only while a job remains `PENDING`. Running storage
commands are not assumed safely interruptible, so cancellation returns a
conflict once work starts. Stage 3 uses a bounded in-process worker pool; native
command process isolation and service packaging remain future hardening work.

## Agent enrollment and synchronization

Operator authentication creates a short-lived, single-use enrollment token.
The local agent exchanges it once for an agent ID and an independently scoped
Bearer token. Central persists hashes rather than plaintext tokens and can
revoke an agent immediately. Agent status is derived from the last authenticated
heartbeat and the configured offline threshold.

Inventory records are owned by an authenticated agent and upserted by stable
hardware identity. Path changes become observations rather than new assets.
Central jobs reference one of those synchronized assets; callers do not submit
an arbitrary target path. Claims are atomic and only the assigned agent can
receive or update a job.

```text
QUEUED -> CLAIMED -> WAITING_LOCAL_APPROVAL -> RUNNING/VERIFYING
                                                   |
                                                   +-> VERIFIED
                                                   +-> FAILED/INCONCLUSIVE/UNSUPPORTED/CANCELLED
```

Dry runs may be auto-submitted only when the local configuration permits it.
Destructive requests always require a separate local approval. Before local
submission, discovery must match the claimed stable identity and must still
show a non-system, safely profiled device. There is no remote shell or generic
command endpoint.

Progress uploads have monotonic sequences and are idempotent. Only a terminal
result upload can finalize the central record; a progress event cannot create a
verified claim. A `VERIFIED` result is accepted only when its verification,
evidence integrity, and successful certificate claim are structurally
consistent. Invalid claims are quarantined as `INCONCLUSIVE`.

The durable outbox stores heartbeat, inventory, progress, and final payloads
before delivery and retries with bounded exponential backoff. Secrets, including
agent credentials and ATA passwords, are rejected from outbox payloads.

## Packaged Linux runtime

```text
systemd
  +-- vyper-agent.service   root, 127.0.0.1:8765
  |      +-- /var/lib/vyper/local-jobs.db
  |      +-- /etc/vyper/agent-identity.json (0600)
  |      +-- outbound HTTPS synchronization
  |
  +-- vyper-console.service   vyper-ui, 127.0.0.1:8787
         +-- /opt/vyper/ui static export (read-only)
```

`/opt/vyper` contains immutable application/runtime files. `/etc/vyper`
contains protected configuration and identity, `/var/lib/vyper` contains
durable jobs and outbox state, and `/var/log/vyper` is reserved for operational
logs. Upgrades replace only immutable files. Ordinary uninstall preserves all
mutable records; `--purge` explicitly removes them.

The initial privilege split keeps the existing tightly scoped execution API in
one root service and runs the UI separately without privilege. Stage 7 adds a
separate, one-shot `boot_sanitize` initramfs mode for an offline former system
disk; it does not relax the normal service's active-system-disk guard. See
`docs/SYSTEM_DISK_SANITIZATION.md` and `docs/BOOT_ENVIRONMENT.md`.

## Core Pipeline

Device Intake
→ Device Profiler
→ Capability Detection
→ Policy Engine
→ Sanitization Pathway
→ Verification
→ Evidence
→ Certificate
→ Disposition

## Storage Policy

### HDD
Default:
HDD host-level overwrite.

Optional:
ATA device-level erase when supported and explicitly selected.

### SATA SSD
Do not use ordinary host-level overwrite as the normal sanitization fallback.

Prefer cryptographic erase when supported and applicable.

Otherwise use an appropriate device-supported sanitization mechanism.

If no acceptable method exists:
UNSUPPORTED / MANUAL HANDLING.

### NVMe
Inspect device capabilities.

Prefer cryptographic erase when supported and applicable.

Otherwise select an appropriate supported NVMe sanitization mechanism.

Never assume every NVMe device supports the same mechanism.

Never silently fall back to generic host overwrite.

## NVMe SANICAP

bit 0 = Crypto Erase
bit 1 = Block Erase
bit 2 = Overwrite

## Core Separation

Profiler = WHAT?
Policy = WHICH?
Pathway = HOW?
Verifier = DID IT WORK?
Evidence = WHAT CAN WE PROVE?
Certificate = WHAT CAN WE CERTIFY?

## Fundamental Rule

Execution success does not automatically equal sanitization verification.

## Safety

No destructive operation without:
- explicit target
- device identity confirmation
- safety checks
- explicit authorization

Dry-run/mock mode must exist.

Unsupported/failed operations must never receive a successful sanitization certificate.
