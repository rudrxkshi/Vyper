# VYPER 1.0.0-rc1 release-candidate report

## Recommendation

**READY_FOR_DEMO** and **READY_FOR_CONTROLLED_HARDWARE_TEST** using disposable media under [HARDWARE_VALIDATION_PLAN.md](HARDWARE_VALIDATION_PLAN.md).

**NOT READY FOR AN OVERALL PRODUCTION CLAIM.** Non-physical security and deployment controls are implemented, and the Ubuntu/VirtualBox boot workflow is validated. Physical HDD, SATA SSD, and NVMe firmware validation remains pending.

## Validation summary

Final Stage 13 command results for this workspace on 2026-08-26:

- Full Python suite: **428 passed, 1 skipped**. The skip is the explicitly
  conditional PostgreSQL transaction test; one third-party FastAPI/TestClient
  deprecation warning was emitted.
- Dedicated Stage 7 suite: **29 passed** using mocks and non-destructive
  fixtures.
- Frontend contract suite: **26 passed**.
- ESLint: **passed**. Next.js production build: **passed** (three static
  routes).
- SQLite migration: **passed** from an empty temporary database to Alembic
  revision `0002_stage13_mfa_sessions`.
- PostgreSQL migration/rollback: **not run locally** because this Windows host
  has no Docker, WSL distribution, PostgreSQL service, or
  `VYPER_TEST_POSTGRES_URL`. The release CI gate provisions PostgreSQL 17 and
  requires both migration and rollback tests; local absence is not recorded as
  a pass.
- Dependency audits: Python `pip-audit` reported no known vulnerabilities;
  `npm audit --audit-level=high` reported 0 vulnerabilities.
- Focused Stage 13/security/packaging suite: **32 passed, 1 skipped** in temporary roots; no
  real systemd installation occurred.
- Stage 8 contract/artifact suite: **2 passed**. Release checksum, manifest
  version, required contents, forbidden paths/suffixes, and secret markers
  validated successfully.
- Release artifact and CycloneDX SBOM passed checksum, manifest, dependency,
  forbidden-path, and secret-marker validation. The distributable remains
  explicitly `UNSIGNED / CHECKSUM_ONLY` until an operator attaches an Ed25519
  signature from an external key and configures the matching trusted key.
- Boot artifact and VirtualBox system-HDD lifecycle are VM validated by retained
  Stage 10/11 evidence. Secure Boot status on this Windows validation host is
  `UNKNOWN` because `mokutil` is unavailable; no key enrollment was attempted.
- `git diff --check`: passed; Git emitted line-ending conversion notices only.

## Supported flows

Mocked and fixture validation covers HDD overwrite, ATA Secure Erase, NVMe Crypto/Block/Overwrite sanitize routing and verification, durable asynchronous jobs, outbound central synchronization, evidence/certificate integrity, and system-disk dry-run boot integration. See [FINAL_AUDIT.md](FINAL_AUDIT.md) and [HARDWARE_VALIDATION_MATRIX.md](HARDWARE_VALIDATION_MATRIX.md).

## Release blockers

Two P0 correctness defects found during Stage 8 were fixed: the ineffective worker dry-run override and acceptance of unhashed successful results. No P1 blocker remains in source/tests. Real-hardware and boot-chain validation gaps are explicitly retained as non-production limitations, not silently treated as passed.

## Security and hardware disposition

All 14 security invariants in [FINAL_AUDIT.md](FINAL_AUDIT.md) are **PASS** in
source review and automated tests. HDD, ATA Secure Erase, and NVMe sanitize
flows pass mocked/image validation but remain untested on physical hardware.
SATA crypto erase remains explicitly unsupported. System-disk sanitization is
VM validated for the VirtualBox HDD workflow; Secure Boot and physical HDD,
SATA SSD, and NVMe firmware execution remain unvalidated.

Known limitations are maintained in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md);
the controlled next step is the disposable-media procedure in
[HARDWARE_VALIDATION_PLAN.md](HARDWARE_VALIDATION_PLAN.md).
# Stage 13 readiness classification

- `PRODUCTION_READY_COMPONENT`: typed Unix-socket root-helper boundary; central MFA/session enforcement; Ed25519 verification; deterministic SBOM generation; PostgreSQL migration and backup/restore harnesses; non-root containers and health/readiness paths.
- `SOFTWARE_VALIDATED`: HDD/ATA/NVMe policy, routing, safety, evidence, certificate, API, persistence, boot tooling, and security regression tests use mocks or fixtures where destructive behavior would otherwise occur.
- `VM_VALIDATED`: real Ubuntu initramfs dry-run and destructive VirtualBox system-HDD workflow passed.
- `PHYSICAL_VALIDATION_PENDING`: physical HDD, SATA SSD, and NVMe controller/firmware behavior has not been validated.
- `PRODUCTION_BLOCKER`: model-specific physical validation and organization-specific Secure Boot key enrollment remain required before a universal production claim.

VYPER 1.0.0-rc1 is not declared generally production-ready; the 1.0 RC version does not replace missing physical, Secure Boot, PostgreSQL, or container evidence.
