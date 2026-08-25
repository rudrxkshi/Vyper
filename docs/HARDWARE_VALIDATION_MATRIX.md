# Hardware validation matrix

Status is based on repository tests as of `1.0.0-rc1`. “VM tested” means mocked or disposable image validation; it does not establish firmware behavior. No physical drive has been destructively tested by this repository session.

| Device class | Interface | Required capability | VYPER pathway | Verification method | VM tested | Physical tested | Status | Known limitations |
|---|---|---|---|---|---:|---:|---|---|
| HDD | SATA/ATA | Writable whole disk | `HDD_OVERWRITE` | Measured byte completion plus representative deterministic raw-read samples | Yes, mocked/image | No | PHYSICAL_VALIDATION_PENDING | Samples do not read every sector; remapping and hidden areas remain controller concerns. |
| SATA SSD | ATA | ATA security supported, not frozen; transient password | `ATA_ERASE` | Post-command ATA security state reported disabled and unfrozen | Yes, mocked | No | PHYSICAL_VALIDATION_PENDING | Controller-reported state; host readback cannot prove every NAND cell was overwritten. |
| SATA SSD | ATA | Evidence-backed device crypto erase | None implemented | None | Routing refusal tested | No | UNSUPPORTED | Policy may identify the capability, but VYPER safely returns `UNSUPPORTED`; it never substitutes ATA erase or NVMe sanitize. |
| NVMe SSD | PCIe/NVMe | SANICAP Crypto Erase and applicability evidence | `CRYPTO_ERASE` via NVMe sanitize | NVMe sanitize log `SSTAT` controller-reported successful completion | Yes, mocked | No | PHYSICAL_VALIDATION_PENDING | Requires controller and namespace compatibility; no claim about every NAND cell. |
| NVMe SSD | PCIe/NVMe | SANICAP Block Erase | `BLOCK_ERASE` via NVMe sanitize | NVMe sanitize log `SSTAT` | Yes, mocked | No | PHYSICAL_VALIDATION_PENDING | Firmware operation has indeterminate progress unless trustworthy status exists. |
| NVMe SSD | PCIe/NVMe | SANICAP Overwrite | `NVME_OVERWRITE` via NVMe sanitize | NVMe sanitize log `SSTAT` | Yes, mocked | No | PHYSICAL_VALIDATION_PENDING | Device-native overwrite, not generic host overwrite. |
| System HDD | SATA/ATA | Stable identity, GRUB2 boot handoff, offline topology | `HDD_OVERWRITE` in `boot_sanitize` | Existing HDD verifier plus boot identity/safety evidence | VM destructive boot validation: PASS | No | VM_DESTRUCTIVE_BOOT_VALIDATED | VirtualBox HDD-like VDI only; physical-media validation remains not applicable and no physical drive was tested. |
| System SATA SSD | SATA/ATA | Stable identity and supported ATA erase | `ATA_ERASE` in `boot_sanitize` | Existing ATA verifier plus boot evidence | Dry-run fixture | No | PARTIAL | ATA password must be re-entered; frozen devices and SATA crypto erase remain unsupported. |
| System NVMe | PCIe/NVMe | Stable NGUID/EUI/WWN, SANICAP, supported boot chain | Selected NVMe sanitize method in `boot_sanitize` | NVMe sanitize log plus boot evidence | Dry-run fixture | No | PARTIAL | Secure Boot trust, GRUB behavior, and physical firmware are unvalidated. |

“READY_FOR_CONTROLLED_HARDWARE_TEST” is not a production-support claim. Record each tested model, firmware, bridge/controller, kernel, and observed evidence separately.
