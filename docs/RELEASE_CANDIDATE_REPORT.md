# VYPER 0.8.0-rc1 release-candidate report

## Recommendation

**READY_FOR_DEMO** and **READY_FOR_CONTROLLED_HARDWARE_TEST** using disposable media under [HARDWARE_VALIDATION_PLAN.md](HARDWARE_VALIDATION_PLAN.md).

**NOT_READY_FOR_PRODUCTION.** Physical ATA/NVMe coverage, bootable initramfs/GRUB validation, managed release signing, MFA, and production operational evidence remain incomplete.

## Validation summary

Final command results for this workspace on 2026-08-25:

- Full Python suite: **283 passed, 1 skipped**. The skip is the explicitly
  conditional PostgreSQL transaction test; one third-party FastAPI/TestClient
  deprecation warning was emitted.
- Dedicated Stage 7 suite: **29 passed** using mocks and non-destructive
  fixtures.
- Frontend contract suite: **26 passed**.
- ESLint: **passed**. Next.js production build: **passed** (three static
  routes).
- SQLite migration: **passed** from an empty temporary database to Alembic
  revision `0001_stage6_baseline`.
- PostgreSQL migration/rollback: **not run locally** because this Windows host
  has no Docker, WSL distribution, PostgreSQL service, or
  `VYPER_TEST_POSTGRES_URL`. The release CI gate provisions PostgreSQL 17 and
  requires both migration and rollback tests; local absence is not recorded as
  a pass.
- Dependency audits: Python `pip-audit` reported no known vulnerabilities;
  `npm audit --audit-level=high` reported 0 vulnerabilities.
- Packaging/fresh-install/upgrade suite: **15 passed** in temporary roots; no
  real systemd installation occurred.
- Stage 8 contract/artifact suite: **2 passed**. Release checksum, manifest
  version, required contents, forbidden paths/suffixes, and secret markers
  validated successfully.
- Boot artifact: the deterministic **non-bootable test fixture** passed hash,
  version, component, and no-credential checks. A real initramfs/GRUB image was
  not buildable or boot-tested on this host.
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
partial: manifest, identity, replay, confirmation, dry-run, and isolated result
handling pass, while real GRUB/initramfs/Secure Boot and hardware execution are
untested.

Known limitations are maintained in [KNOWN_LIMITATIONS.md](KNOWN_LIMITATIONS.md);
the controlled next step is the disposable-media procedure in
[HARDWARE_VALIDATION_PLAN.md](HARDWARE_VALIDATION_PLAN.md).
