# Known limitations — 1.0.0-rc1

- Local Console and boot tooling support Linux x86_64 only, currently targeting Ubuntu/Debian.
- System-disk handoff supports GRUB2 one-shot boot only. Windows, macOS, systemd-boot, kexec, ARM, and manual USB workflows are not implemented.
- Secure Boot status and MOK enrollment readiness are detected read-only, but VYPER does not universally automate firmware trust or claim support across all shim/firmware combinations.
- The boot environment supports common wired DHCP only; Wi-Fi is not supported.
- Active or unknown mdraid, LVM, device-mapper, crypt, multipath, mounts, swap, holders, or boot-root relationships are refused.
- SATA cryptographic erase has no implemented evidence-backed pathway. It returns `UNSUPPORTED` and is never substituted.
- ATA and NVMe pathways are comprehensively mocked but have not been fully validated on representative physical hardware.
- VirtualBox can validate orchestration and an HDD-like VDI overwrite, but cannot prove ATA Secure Erase or NVMe firmware sanitize behavior.
- HDD verification uses representative reads; ATA/NVMe verification uses method-specific controller state. None claims every NAND cell contains a chosen pattern.
- The current checked-in release is checksum-only. Ed25519 verification is implemented, but publisher identity exists only for artifacts signed externally and verified through a shipped trusted public key.
- The local executor remains a privileged root process with residual attack surface, although it exposes fixed storage operations rather than a generic command API.
- TOTP MFA is available and required for destructive central jobs. Recovery codes must be protected by the operator; endpoint compromise and database-administrator threats remain.

- Physical HDD, SATA SSD, and NVMe firmware validation remains `PHYSICAL_VALIDATION_PENDING`. Software and VirtualBox validation do not establish physical-media behavior.
- Metrics are process-local and reset on restart.
- Audit chaining is tamper-evident at application level, not tamper-proof against a database administrator or compromised host.
- Boot-job HMAC protection assumes the installed local root trust boundary; local root compromise can replace both key and artifact.
- Offline boot evidence is durable only when a non-target persistent destination is explicitly provided. Default initramfs memory does not survive shutdown.
- The current development host has no Linux/WSL/Docker environment, so the host-specific bootable initramfs and real GRUB handoff remain untested here.
