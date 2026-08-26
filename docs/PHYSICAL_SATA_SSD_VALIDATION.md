# Controlled physical SATA SSD validation

This procedure validates one explicitly selected disposable SATA SSD through VYPER's existing controller-native `ATA_ERASE` pathway. It does not add an HDD-overwrite fallback, SATA crypto erase, or NVMe validation.

> **Use only a disposable SSD. Triple-check the physical model, serial, WWN, capacity, and direct SATA connection. Never use this workflow on production data.**

## Evidence boundary

ATA Secure Erase is a controller-native command. VYPER's successful claim relies on command completion, the existing method-specific verifier observing ATA Security disabled and unfrozen afterward, valid evidence/certificate integrity, and independent logical/interface checks that do not contradict the controller state.

Wear leveling, remapped blocks, spare NAND, and over-provisioned areas mean host logical readback cannot prove that every NAND cell contains a chosen value. Stage 9B does not claim that every NAND cell is zero or that every spare block was independently read.

The validation harness never calls destructive `hdparm` commands directly. Execution follows:

```text
vyper CLI
  -> loopback local API v2
  -> durable local job
  -> VYPERAgent policy
  -> ATAErasePathway
  -> ATA verifier
  -> evidence and certificate
```

## Safety checklist

- [ ] The SSD is disposable and contains no needed data.
- [ ] The device is directly attached over SATA/ATA when possible.
- [ ] The printed serial/WWN matches the physical label.
- [ ] Model and capacity match the intended SSD.
- [ ] `rotational` is `false` and device type is `SATA SSD`.
- [ ] The SSD and its children are unmounted.
- [ ] It is not associated with the running system.
- [ ] ATA Security and Secure Erase are positively reported as supported.
- [ ] ATA Security is not frozen.
- [ ] No unexpected USB bridge or unknown pass-through layer is present.
- [ ] The local VYPER agent is running on loopback.

If the device is frozen, stop. Stage 9B does not implement suspend/resume, hot-plug, or automatic power-cycle tricks to unfreeze it.

## 1. Read-only planning

There is no default device and wildcards are rejected:

```bash
sudo vyper validate-hardware sata-ssd --device /dev/sdX
```

Plan mode performs read-only profiling, ATA identify/capability inspection, and filesystem/topology inspection. It prints:

- path, model, serial, WWN, capacity, transport, interface, and rotational classification;
- system and mount state;
- ATA Security supported/enabled/frozen state;
- Secure Erase and Enhanced Secure Erase support;
- estimated erase-time and ATA version lines when the controller exposes them;
- selected VYPER pathway `ATA_ERASE`;
- explicit execution blockers.

No ATA password is requested and no sanitization job is submitted in plan mode.

## 2. Optional disposable-data preparation

Preparation creates only a small deterministic test dataset; it does not fill the SSD. Inspect its plan:

```bash
sudo vyper validate-hardware sata-ssd prepare --device /dev/sdX
```

To format the disposable device and create data, repeat with `--execute` and type the displayed `PREPARE <suffix>` phrase:

```bash
sudo vyper validate-hardware sata-ssd prepare --device /dev/sdX --execute
```

The helper creates ext4, mounts a controlled path, writes `secret.txt`, `sample.bin`, and deterministic `random.bin`, records sizes and SHA-256 hashes plus the filesystem UUID, calls `sync`, and unmounts. A `*-sata-ssd-*-test-data.json` manifest is retained.

## 3. Execute through VYPER

Re-run the plan and inspect every field, then explicitly arm execution:

```bash
sudo vyper validate-hardware sata-ssd --device /dev/sdX --execute
```

The command displays the exact identity and requires:

```text
Type exactly 'ERASE <serial-or-WWN-suffix>' to continue:
```

After confirmation it profiles again, rechecks identity, capacity, classification, mounts, ATA support, bridge context, and frozen state. It then requests the transient ATA password using hidden terminal input. The harness does not print or persist the plaintext password. The existing local job pipeline clears and redacts it after use; reports record only `ata_password_used: true`.

ATA firmware progress remains `indeterminate` unless trustworthy device progress exists. Stage 9B never converts elapsed time into a percentage.

## 4. Independent read-only checks

After the durable job reaches a terminal state, the harness runs:

- `lsblk --fs` JSON inspection;
- `blkid -p`;
- `file -s`;
- `udevadm info --query=property`;
- `hdparm -I`;
- `smartctl -i` when available.

It records filesystem/UUID evidence, file signature, model, serial, WWN, capacity, controller accessibility, and post-erase ATA Security state. Logical zero sampling is not a primary SATA SSD criterion.

If the prepared filesystem remains clearly recognized, the result is at least `INCONCLUSIVE`, regardless of a controller success claim. No aggressive forensic recovery is performed.

## 5. Conclusions and reports

Execution produces:

```text
hardware-validation/<timestamp>-sata-ssd-<stable-id>.json
hardware-validation/<timestamp>-sata-ssd-<stable-id>.md
```

`PASS` requires stable identity/classification, `ATA_ERASE`, VYPER `VERIFIED`, verifier success, successful certificate claim, valid bound evidence/certificate hashes, reported erase-command completion, ATA Security disabled and unfrozen, controller accessibility, and no contradictory independent check.

`FAILED` VYPER execution produces `FAIL`. Missing controller state, failed required probes, remaining filesystem signatures, integrity mismatch, or contradictory state produces `INCONCLUSIVE`.

Existing execution metadata does not currently expose separate structured results for every successful set-password and erase-prepare command. The validation report records those fields as unavailable rather than inventing evidence; it records the existing aggregate erase-completion and post-status metadata truthfully.

Mock report-shape examples are available at:

- `tests/fixtures/hardware_validation/sample_sata_ssd_validation.json`
- `tests/fixtures/hardware_validation/sample_sata_ssd_validation.md`

They are not physical-hardware evidence.
