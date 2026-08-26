# Stage 8 final architecture and security audit

## End-to-end flow disposition

| Flow | Source trace | Result | Evidence boundary |
|---|---|---|---|
| Secondary HDD | UI/API → `DeviceDiscovery` → durable local job → authorization → `PolicyEngine` → `HDDOverwritePathway` → measured progress → `Verifier` sampling → evidence/certificate → durable outbound upload | PASS in mocks/images; UNTESTED_ON_REAL_HARDWARE | Representative host reads; hidden/remapped areas are outside the claim. |
| SATA SSD | Discovery/`hdparm` profile → capability policy → `ATAErasePathway` → ATA-state verification → evidence | PARTIAL; ATA path PASS in mocks, SATA crypto BLOCKED as explicitly unsupported; UNTESTED_ON_REAL_HARDWARE | Controller-reported security state, not every NAND cell. |
| NVMe SSD | Discovery/identify-controller SANICAP → capability policy → selected NVMe sanitize action → sanitize-log/SSTAT verification → evidence | PASS in mocks; UNTESTED_ON_REAL_HARDWARE | Controller-reported sanitize completion. |
| System disk | CLI prepare → authenticated manifest/state → one-shot GRUB → `boot_sanitize` → exact identity/topology checks → fresh confirmation → existing pathway → evidence/upload/shutdown | PARTIAL; dry-run fixture PASS, real boot/hardware UNTESTED | Host-specific initramfs/GRUB/Secure Boot require controlled Linux validation. |

## Release-blocker classification

- **P0 fixed:** process-worker `VYPER_EXECUTOR_DRY_RUN=true` did not override a destructive per-job flag. Effective dry run is now the logical OR; the installed production unit opts out explicitly.
- **P0 fixed:** central direct and agent-protocol paths could accept a structurally successful `VERIFIED` claim without mandatory evidence/certificate hashes. Successful claims now require valid, mutually bound SHA-256 evidence and certificate integrity plus matching verification/status fields. Invalid claims are rejected or quarantined as `INCONCLUSIVE`.
- **P1 open:** none identified after fixes and regression tests.
- **P2:** actual bootable initramfs/GRUB, ATA/NVMe firmware behavior, and representative physical hardware remain unvalidated; application audit-chain insertion can require database-level serialization under very high concurrency.
- **P3:** checksum-only publishing, no MFA, process-local metrics, and platform breadth remain documented limitations.

## API and evidence audit

Frontend/local request nesting matches both Pydantic models. Local API stays at v2 and central agent protocol at v1. The shared golden fixture covers local authorization, central `execution_mode`, and boot lifecycle events. Central free-form targets and ATA passwords remain forbidden. Evidence and certificates use canonical sorted JSON, SHA-256, recursive secret-key redaction, target/profile/pathway/execution/verification/limitations/timestamps, and method-specific status. Boot evidence adds `execution_environment: boot_sanitize` and boot/central job IDs. Normal local evidence has an engine job ID while local/central correlation remains in the durable job/protocol envelopes.

## Security invariants

| Invariant | Result |
|---|---|
| Browser cannot execute arbitrary root commands | PASS |
| Central cannot directly access local block devices | PASS |
| Agent sync is outbound | PASS |
| Remote destructive jobs require local approval | PASS |
| System disk cannot be wiped in normal mode | PASS |
| Boot mode re-identifies exact target | PASS |
| Unknown identity/safety blocks execution | PASS |
| Interrupted jobs cannot become `VERIFIED` | PASS |
| Same target cannot have concurrent destructive jobs | PASS |
| Secrets absent from logs/API/artifacts | PASS in automated scans/redaction tests |
| Revoked agent cannot sync | PASS |
| Evidence/certificate mismatch is quarantined | PASS |
| Privileged executor has no generic command endpoint | PASS |
| Boot-job replay is prevented | PASS |

No source/UI documentation used “100% unrecoverable,” “military-grade,” “fully NIST compliant,” “every NAND cell erased,” or “tamper-proof audit log.” “Permanently destroy” remains only in explicit destructive-confirmation warnings, where it accurately describes loss of the OS and accessible data.

