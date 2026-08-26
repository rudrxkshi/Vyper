# VYPER 1.0.0-rc1 release notes

VYPER is a Linux storage-sanitization platform combining a downloadable local console, a privilege-separated local agent, and an optional central operations dashboard. This release candidate is for demonstrations, controlled VM deployment, and controlled disposable-hardware validation—not universal production deployment.

## Product and platform

The release artifact targets Linux x86_64, primarily Ubuntu, with Debian compatibility subject to site validation. Windows and macOS execution, Wi-Fi in the boot environment, and ambiguous RAID/LVM/multipath targets are unsupported.

Local jobs are durable and asynchronous. The central dashboard manages users, assets, jobs, results, certificates, and audit history. Remote agents enroll once and make authenticated outbound connections, allowing machines behind NAT to receive work without exposing a disk-control listener. A remote destructive request requires an authenticated MFA-authorized operator and separate local confirmation.

## Storage methods

- Rotational HDDs use the existing overwrite pathway and logical sampling verifier.
- SATA SSD ATA Secure Erase remains separate and requires supported, unfrozen direct-ATA media. No automatic unfreeze occurs.
- SATA crypto erase is explicitly unsupported; it is never substituted with ATA erase or NVMe sanitize.
- NVMe Crypto Erase, Block Erase, and native Overwrite use the NVMe controller target after unambiguous namespace-to-controller resolution and SANICAP checks.

The no-USB system-disk workflow builds a host-specific initramfs, creates a GRUB2 one-shot entry, re-identifies the disk offline, obtains local approval, preserves evidence, and restores the normal GRUB default. Real Ubuntu dry-run boot and destructive VirtualBox HDD validation have passed.

## Integrity and security

Evidence and certificates use canonical SHA-256 integrity checks and distinguish raw pathway status, orchestration terminal status, verification status, final sanitization status, and post-result shutdown status. A terminal VERIFIED result cannot present the user-facing execution state as active.

Central access includes RBAC, MFA, rotating bounded sessions, secure cookies, and CSRF checks. Native execution is isolated behind a typed AF_UNIX root helper with no network listener or arbitrary-command interface. Releases include a CycloneDX SBOM and checksums. This artifact is truthfully marked unsigned/checksum-only unless a detached Ed25519 signature from an external key is deliberately attached.

## Validation status

- `SOFTWARE_VALIDATED`: API integration, persistence, routing/safety, verification, evidence/certificates, boot tooling, authentication, signing verification, packaging, and security invariants.
- `VM_VALIDATED`: real Ubuntu initramfs/GRUB dry-run and destructive VirtualBox system-HDD workflow.
- `PHYSICAL_VALIDATION_PENDING`: physical HDD, SATA SSD, and NVMe firmware/controller behavior.

Real Secure Boot validation, a local PostgreSQL 17 backup/restore drill, and local container smoke testing remain environment-dependent and pending on the current Windows host. See the [compatibility matrix](docs/COMPATIBILITY_MATRIX.md), [hardware matrix](docs/HARDWARE_VALIDATION_MATRIX.md), and [known limitations](docs/KNOWN_LIMITATIONS.md).
