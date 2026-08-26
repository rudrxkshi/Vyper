# VYPER controlled physical SATA SSD validation — mock fixture

> This is a report-shape fixture. No physical SSD was tested.

- Conclusion: **PASS (mock inputs only)**
- VYPER version: `1.0.0-rc1`
- Device: `/dev/sdy`
- Model: `DISPOSABLE MOCK SATA SSD`
- Serial: `MOCK-SATA-123456`
- Capacity: `128000000000` bytes

## ATA capabilities

- ATA Security supported: `true`
- Secure Erase supported: `true`
- Enhanced Secure Erase supported: `true`
- Frozen before execution: `false`

## Product-path result

- Selected pathway: `ATA_ERASE`
- VYPER verification: `VERIFIED`
- Progress: `indeterminate`; no percentage claimed
- Evidence and certificate mock hashes: present and mutually bound in the fixture

## Independent post-checks

- Controller accessible: `true`
- ATA Security enabled after operation: `false`
- ATA Security frozen after operation: `false`
- Old filesystem recognized: `false`

## Verification basis

- Controller/native command evidence
- VYPER verifier
- Independent logical/interface checks

## Conclusion

The controller-native ATA erase completed, VYPER verified the device-reported post-state, and independent logical/interface checks found no contradictory old filesystem evidence.

This mock fixture does not prove physical NAND behavior. Logical checks do not prove every NAND cell, remapped block, spare block, or over-provisioned area independently.
