# Controlled physical-hardware validation plan

Use only explicitly disposable drives in an isolated Linux test host. Disconnect production drives where practical. Never use a disk that contains the only copy of any data, a production OS, or an operator’s workstation data. Two people should independently compare the intended model, serial, capacity, and transport before authorizing a destructive test.

## Common pre-test record

1. Photograph or record the physical drive label and connection topology.
2. Record exact model, serial, capacity, interface/transport, firmware, controller/bridge, kernel, and whether it is a system disk.
3. Confirm backups are irrelevant because the drive is disposable. Record the approver and timestamp.
4. Create a fresh test filesystem and uniquely named sample files containing non-sensitive random test data.
5. Record filesystem UUID/type, partition table, file list, and SHA-256 checksums.
6. Unmount all target partitions, disable target swap, and capture `lsblk`, VYPER discovery, and profile output.
7. Compare VYPER’s stable identity with the physical label. Stop on missing, ambiguous, or changed identity.

## Secondary SATA HDD

Execution: verify policy selects `HDD_OVERWRITE`, record explicit local authorization, observe measured bytes rather than inferred percentage, and retain the terminal evidence/certificate.

Post-test: confirm no filesystem signature remains, attempt a read-only mount, perform representative raw reads at the beginning/middle/end and VYPER’s sampled offsets, re-profile the drive, and review evidence/certificate hashes and the audit-chain link. Representative reads are validation samples, not proof that every remapped or hidden physical sector was overwritten.

## SATA SSD with ATA Secure Erase

Pre-test additionally records ATA security supported/enabled/frozen state and enhanced-erase capability. Do not proceed through an unknown bridge or frozen state. Supply a test-only transient ATA password through the local approval surface; never place it in notes or logs.

Execution: confirm `ATA_ERASE` is selected, record controller command completion and transition to verification. Do not relabel an unsupported SATA crypto policy as ATA erase.

Post-test: capture ATA security state, filesystem detection, read-only mount attempt, representative raw reads, re-profile, and inspect evidence limitations. Host-level readback and ATA status do not prove every NAND cell was overwritten; hidden, remapped, over-provisioned, or failed NAND remains controller-dependent.

## NVMe Crypto, Block Erase, and Overwrite

Pre-test records controller/namespace identifiers, NGUID/EUI-64/WWN, SANICAP bits, namespace size, firmware, and the exact requested method. Test each method only on hardware explicitly reporting that capability.

Execution: verify the selected method exactly matches policy and command metadata. Capture sanitize-log state; show indeterminate progress unless the protocol exposes trustworthy progress.

Post-test: capture final sanitize log/SSTAT, namespace/filesystem detection, representative reads, read-only mount attempt, re-profile, and evidence/certificate integrity. Controller-reported completion is method-specific evidence, not proof that every NAND cell contains a particular pattern.

## System-disk variants

Use a dedicated disposable test machine. Complete the common pre-test record, verify the normal OS refuses the active disk, prepare an expiring one-shot job, photograph the GRUB and Secure Boot state, and confirm the normal default remains unchanged. In boot mode independently compare stable identifiers, topology checks, selected method, and the fresh `ERASE <suffix>` prompt. After terminal evidence, verify shutdown rather than reboot into the erased OS. Test boot-failure recovery and power loss first with dry-run jobs; destructive tests require a separate approved hardware protocol.

## Required post-test packet

- Pre/post discovery and hardware profile
- Test-data checksums and filesystem metadata
- Selected policy/pathway and authorization record
- Measured or explicitly indeterminate progress record
- Execution and verification payloads
- Evidence JSON and integrity check
- Certificate/outcome report and integrity check
- Central correlation and audit-chain verification
- Deviations, warnings, limitations, and operator sign-off

