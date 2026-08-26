# VYPER

VYPER profiles storage, selects a device-appropriate sanitization pathway, verifies the outcome, and produces integrity-protected evidence and certificates. It combines a downloadable Linux local console with an optional central dashboard. VYPER 1.0.0-rc1 is ready for demonstrations and controlled VM or disposable-hardware testing; it is not universally production-ready.

## Architecture

The browser talks to an unprivileged local API or the central FastAPI service. Local storage access crosses a typed, allowlisted Unix-socket boundary into the root executor. Remote agents initiate outbound authenticated synchronization, so the central service never directly opens or controls local disks through NAT.

## Central backend

The central API lives under `backend/app/`. It persists assets, jobs, results,
certificates, and audit logs. It can use the in-process agent gateway for local
development or the dedicated local-agent transport when configured.

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
- `POST /agents/enrollment-tokens`
- `POST /agents/enroll`
- `POST /agent/heartbeat`
- `PUT /agent/inventory`
- `GET /agent/jobs/next`
- `POST /agent/jobs/{central_job_id}/events`
- `POST /agent/jobs/{central_job_id}/result`

Central `GET /devices` is a backward-compatible alias for persisted assets. It
does not discover the central host or a remote operator machine.

## Local execution service

On Linux, start the dedicated local agent with:

```bash
python -m local_agent.main
```

It binds to `127.0.0.1:8765` by default and exposes only:

- `GET /health`
- `GET /devices` for live, read-only device discovery
- `POST /jobs/sanitize`
- `GET /jobs` for durable local history
- `GET /jobs/{local_job_id}`
- `POST /jobs/{local_job_id}/cancel` for pending jobs only
- `POST /sync/enroll`
- `GET /remote-jobs`
- `POST /remote-jobs/{central_job_id}/approve`

Set `VYPER_LOCAL_AGENT_API_KEY` to require `X-VYPER-API-Key`. The default CORS
origins are the local dashboard at `http://127.0.0.1:3000` and
`http://localhost:3000`; override them with a comma-separated
`VYPER_LOCAL_AGENT_CORS_ORIGINS`. Public binding is refused unless both
`VYPER_LOCAL_AGENT_HOST` and `VYPER_LOCAL_AGENT_ALLOW_PUBLIC=true` are set
deliberately.

Local API version 2 returns `202 Accepted`, executes through a bounded worker
pool, and persists lifecycle state and sequenced events in SQLite. Configure the
database with `VYPER_LOCAL_AGENT_DATABASE_PATH`; the default is
`local_agent/vyper_local.db`. The dashboard polls durable job state.

On restart, completed jobs remain readable, pending jobs are safely cancelled,
and interrupted active jobs become `INCONCLUSIVE`; they never become verified
without durable verification evidence. HDD progress uses measured bytes. ATA
and NVMe operations are shown as indeterminate when no trustworthy numeric
progress exists.

## Central synchronization (agent protocol v1)

Set `VYPER_CENTRAL_URL` on the local agent, create a short-lived one-use
enrollment token through the operator-authenticated central API, and submit it
to local `POST /sync/enroll`. Enrollment credentials are stored locally with
owner-only permissions; central stores only token hashes. Agent requests use a
separate Bearer credential from the operator `X-VYPER-API-Key`.

The local agent initiates every central connection. During enrollment it creates
an endpoint-local Ed25519 keypair, registers only its public key and a
privacy-preserving endpoint fingerprint, and pins the central command
verification key returned by the enrollment response. It sends heartbeat and
inventory updates, polls for a signed assigned job, and uploads sequenced
progress and one terminal result through a durable SQLite outbox with bounded
retry.
This works through ordinary outbound NAT without exposing the local API.

Destructive remote requests always stop at `WAITING_LOCAL_APPROVAL`. Before an
assignment can reach that state, the agent verifies the Ed25519 signature,
central signing-key identity, intended agent, allowlisted operation, issue/expiry
times, and durable command nonce. The local console then re-discovers the device
and checks its stable identity and system-device status before creating a local
job. Central authorization is recorded but does not replace local approval. ATA
passwords are transient and are never placed in the central request or durable
outbox.

Synchronization remains polling-based and outbound-only; the central service
does not open an inbound control channel to the local machine.

## Linux Local Console package

The release build produces `release/vyper-local-console-linux-x86_64-1.0.0-rc1.tar.gz` for
Ubuntu/Debian x86_64. It contains the Python wheel, pinned runtime dependency
lock, static Next.js export, systemd units, installer, conservative uninstaller,
payload checksums, and package manifest.

```bash
sha256sum -c checksums.txt
sudo ./install.sh
sudo vyper enroll
vyper open
```

The unprivileged local agent starts automatically and binds to `127.0.0.1:8765`; only the allowlisted executor helper retains root storage access. The
unprivileged static console binds to `127.0.0.1:8787`. Configuration lives in
`/etc/vyper`, durable databases/outbox in `/var/lib/vyper`, and immutable
application files in `/opt/vyper`. See `docs/INSTALL_LINUX.md` and
`docs/SECURITY_MODEL.md`.

## Linux system-disk boot mode

On supported Ubuntu/Debian x86_64 GRUB2 hosts, the installed console can prepare
a one-shot independent initramfs for system-disk sanitization without USB media.
The running OS never wipes its own active disk: preparation creates an
authenticated, expiring job and fresh confirmation remains mandatory after the
temporary environment re-identifies the physical disk.

```bash
sudo vyper system-disk prepare --dry-run
sudo vyper system-disk reboot --confirm-reboot
```

See `docs/SYSTEM_DISK_SANITIZATION.md`, `docs/BOOT_RECOVERY.md`, and
`docs/SECURE_BOOT.md` for safety checks and platform limitations.

## Supported storage and method selection

- Rotational HDD: `HDD_OVERWRITE` with measured completion and logical read sampling.
- SATA SSD: `ATA_ERASE` only when ATA Secure Erase is supported and the device is not frozen. SATA crypto erase is unsupported and never substituted.
- NVMe SSD: controller-native Crypto Erase, Block Erase, or Overwrite only when SANICAP and namespace/controller scope support the selected method.

Mounted, system, holder-backed, RAID/LVM/multipath, identity-ambiguous, capability-unknown, or otherwise unsafe targets are conservatively refused.

## Verification and reporting

Verification is pathway-specific. Reports distinguish raw historical execution state, orchestration terminal state, verification state, final sanitization state, and boot-environment shutdown state. Only a verified result with valid evidence and certificate integrity can produce a successful sanitization certificate.

## Development and testing

Install the pinned Python and frontend dependencies, then run `python -m pytest tests`, `npm test`, `npm run lint`, and `npm run build` from the dashboard directory. All automated sanitization tests use mocks, fixtures, dry-run paths, or disposable VM evidence. Production central deployments require PostgreSQL at the supported Alembic head; development may use SQLite.

## Release-candidate status

The current version is `1.0.0-rc1`: ready for a controlled demo and disposable
hardware validation, but not production-ready. See
`docs/RELEASE_CANDIDATE_REPORT.md`, `docs/HARDWARE_VALIDATION_MATRIX.md`, and
`docs/KNOWN_LIMITATIONS.md` for the evidence boundary and remaining gaps.

The operator-gated physical HDD harness is documented in
`docs/PHYSICAL_HDD_VALIDATION.md`. It is read-only unless `--execute` and an
exact identity-derived confirmation are both supplied, and it uses the normal
durable local-agent pathway rather than a direct disk command.

Physical HDD, SATA SSD, and NVMe validation remains pending. Real Secure Boot validation and locally executed PostgreSQL/container production drills are also pending. See [release notes](RELEASE_NOTES.md), [compatibility](docs/COMPATIBILITY_MATRIX.md), [final security gate](docs/FINAL_SECURITY_GATE.md), and [validation report](docs/1.0.0-rc1-VALIDATION_REPORT.md).

Controlled disposable SATA SSD validation through the existing controller-native
`ATA_ERASE` pathway is documented in `docs/PHYSICAL_SATA_SSD_VALIDATION.md`.
It refuses frozen drives and unproven USB-to-SATA pass-through, keeps progress
indeterminate, and never substitutes HDD overwrite.

Controlled disposable NVMe planning and validation evidence are documented in
`docs/PHYSICAL_NVME_VALIDATION.md`. The harness is plan-only by default and uses
the normal durable local API path. It preserves namespace asset identity while
issuing controller-scoped sanitize and verification, and refuses controllers
with multiple or incompletely checked namespaces.
