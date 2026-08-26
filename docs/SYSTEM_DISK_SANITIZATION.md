# System-disk sanitization

VYPER has two deliberately separate execution modes:

- `normal_local`: the installed console runs while the host OS is active. The existing system-device guard remains mandatory and rejects destructive execution against the active system disk.
- `boot_sanitize`: a job-specific, independent initramfs runs before the installed root filesystem is mounted. Only this mode may process the former system disk, and only after manifest authentication, expiry and replay checks, exact hardware re-identification, topology checks, and fresh local confirmation.

The supported Stage 7 flow is:

```text
Download/install VYPER -> vyper system-disk prepare -> one-shot GRUB reboot
-> temporary VYPER initramfs -> re-identify and validate physical disk
-> local ERASE <job-suffix> confirmation -> existing VYPER pathway and verifier
-> evidence/upload -> shutdown
```

No USB is required for the supported Ubuntu/Debian x86_64 GRUB2 handoff. Windows, macOS, systemd-boot, direct kexec, Wi-Fi, ARM, and non-GRUB boot handoff are not implemented.

## Commands

```console
$ sudo vyper system-disk prepare --dry-run
System disk: /dev/nvme0n1 | Example NVMe | EXAMPLE123
Boot job: 55d8eb53-242c-45e0-aa23-930d2e76c9ab
System disk sanitization is prepared. No data has been erased yet.
A fresh confirmation will be required inside the temporary boot environment.

$ sudo vyper system-disk status
$ sudo vyper system-disk cancel
$ sudo vyper system-disk reboot --confirm-reboot
```

Non-dry-run preparation also requires `--authorize-system-disk`. Preparation never sanitizes immediately. The reboot command only acts on a job in `AWAITING_REBOOT`.

The boot manifest contains the boot and optional central job IDs, agent ID, an identity digest and expected identifiers, requested policy/method, dry-run flag, timestamps and expiry, authorization and local-confirmation states, boot-image version/hash, a random nonce, and HMAC-SHA256 integrity metadata. Plaintext ATA passwords are never included; ATA credentials must be re-entered at the boot console.

Identity matching uses NGUID, then EUI-64, then WWN, then the complete serial/model/capacity tuple. Device paths are informational only. Missing, changed, or ambiguous identity stops execution. Policy remains capability-based and is passed to the existing `VYPERAgent`; no unsupported method is substituted or downgraded.

The console reports `PREPARING_BOOT`, `AWAITING_REBOOT`, `BOOT_ENVIRONMENT_STARTED`, `VALIDATING_TARGET`, `WAITING_LOCAL_APPROVAL`, `RUNNING`, and the native verification outcome. A remote approval cannot replace local confirmation.

## Storage limitations

Active mdraid, LVM PVs, device-mapper/crypt mappings, visible multipath, holders, mounted children, active swap, or a target backing the boot root are refused. Unknown inspection state is refused. LUKS and BitLocker-style signatures are treated as data signatures; VYPER does not unlock them. Firmware/BIOS RAID that hides member relationships, exotic device stacks, and topologies that cannot be represented by `lsblk`, sysfs holders, and `pvs` are unsupported.

Wired DHCP is attempted. Cloud loss does not change the native sanitization result. When a separately provisioned, non-target durable result directory is configured, set `VYPER_BOOT_RESULT_DIR` and `VYPER_BOOT_RESULT_DURABLE=true`; offline evidence is then marked `RETAINED_OFFLINE`. The default initramfs path is memory-backed and is honestly marked `RETAINED_IN_BOOT_MEMORY`, so it will not survive shutdown. Central upload is therefore strongly recommended when no separate safe storage exists. VYPER never writes recovery evidence onto the disk being sanitized.

