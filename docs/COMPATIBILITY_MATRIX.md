# Compatibility matrix

| Area | State | Notes |
|---|---|---|
| Ubuntu Linux, x86_64 | Supported/validated | Primary local-console and real initramfs validation environment. |
| Debian Linux, x86_64 | Supported package target | Requires deployment-specific integration validation. |
| Other architectures | Unsupported | No release artifact supplied. |
| GRUB2 | Supported/VM validated | One-shot boot preserves the configured default. |
| Secure Boot | Tooling available; real validation pending | `SECURE_BOOT_REAL_VALIDATION_PENDING`; no automatic enrollment or bypass. |
| SATA HDD | Software and VM validated | Physical validation pending. |
| SATA SSD | Software/controller-state mocked | Direct SATA preferred; physical ATA Secure Erase validation pending. |
| NVMe SSD | Software/controller-targeting validated | Physical controller/firmware validation pending. |
| RAID/LVM/multipath | Conservative refusal | Ambiguous ownership/scope is not executed. |
| Boot networking | Wired DHCP | Wi-Fi unsupported in the boot environment. |
| Windows/macOS execution | Unsupported | Windows may be used only as a development/test host. |
