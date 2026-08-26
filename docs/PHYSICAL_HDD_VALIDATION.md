# Controlled physical HDD validation

This procedure validates one explicitly selected disposable rotational HDD through VYPER's normal local product pathway. It is not a production-disk procedure and it does not extend support to SATA SSDs or NVMe devices.

> **Use only a disposable drive. Triple-check its serial, model, WWN, and capacity. Never run this workflow against production data or a drive whose loss would matter.**

## Safety model

The command has no default device and rejects wildcards. Plan mode is the default and performs read-only profiling and `lsblk` inspection only. Execution is blocked when the device is mounted, system-associated, non-rotational, not classified as an HDD, lacks a serial/WWN, has unknown capacity/topology, or changes identity between the plan and the fresh execution profile.

Neither the validation nor preparation harness invokes `dd`. Sanitization is submitted to local API v2 and follows the existing durable path:

```text
vyper CLI
  -> loopback local agent
  -> durable local job
  -> VYPERAgent
  -> HDD_OVERWRITE
  -> existing verifier
  -> evidence and certificate
```

Execution needs all of the following:

- an explicit `--device /dev/...` whole-device path;
- the explicit `--execute` flag;
- a second, matching profile immediately before execution;
- an unmounted, non-system rotational HDD with stable identity;
- exact typed confirmation based on the displayed serial or WWN suffix.

## Prerequisites

- Ubuntu/Debian x86_64 with the VYPER Local Console installed.
- The privileged `vyper-agent` service running on loopback.
- `lsblk`, `blkid`, `file`, `mkfs.ext4`, `mount`, `umount`, and `sync` available.
- Root/operator permission to profile and read the raw disposable disk.
- If local API authentication is enabled, expose its value only to the command process through `VYPER_LOCAL_AGENT_API_KEY`; do not put it in a report or shell history.

Physically disconnect any drive not needed for the test when practical. Confirm backups concern other systems only—the selected disposable test drive will be destroyed.

## 1. Inspect the read-only plan

Replace `/dev/sdX` only after matching the physical label on the disposable drive:

```bash
sudo vyper validate-hardware hdd --device /dev/sdX
```

The command prints path, model, serial, WWN when available, capacity, transport, interface, rotational classification, system-device state, mounts, partitions/filesystem information, planned steps, and the future confirmation phrase. It does not submit a job.

Stop if any field is missing, unexpected, or disagrees with the physical drive label. A `/dev/sdX` name by itself is never accepted as identity.

## 2. Optionally prepare synthetic disposable data

Preparation itself reformats the selected drive, so inspect its plan first:

```bash
sudo vyper validate-hardware hdd prepare --device /dev/sdX
```

To perform preparation, repeat with `--execute` and type the displayed `PREPARE <suffix>` phrase exactly:

```bash
sudo vyper validate-hardware hdd prepare --device /dev/sdX --execute
```

The helper creates an ext4 filesystem directly on the disposable test device, mounts it below the selected report directory, creates deterministic synthetic files under `vyper-validation/`, records their sizes and SHA-256 hashes, calls `sync`, and unmounts. It writes a `*-test-data.json` manifest. It never uses production data.

If unmounting fails, preparation stops and sanitization remains blocked. Resolve the mount and start again from plan mode.

## 3. Recheck and execute through VYPER

First run the plan again and compare every identity field. Then explicitly execute:

```bash
sudo vyper validate-hardware hdd --device /dev/sdX --execute
```

Immediately before submission, VYPER re-profiles the target and redisplays the exact identity. Type `ERASE <suffix>` exactly. A simple `y`, `yes`, or piped default is insufficient.

The harness submits `dry_run: false` with explicit authorization to the loopback local API. It polls the durable job and records only measured `bytes_completed`, `bytes_total`, and event timestamps. Elapsed time is never converted into estimated progress.

Do not unplug, suspend, reboot, or power off the test host while the overwrite is active.

## 4. Review independent post-checks

After a terminal VYPER result, the harness performs read-only checks:

- `lsblk --fs` JSON inspection;
- `blkid -p` signature probing;
- `file -s` classification;
- 4 KiB raw reads at the logical beginning, middle, and end of the drive.

For the current zero-write HDD pathway, all three samples must contain zero bytes for an independent consistency pass. The report records offsets, sizes, bytes read, hashes, and match results.

VYPER's HDD verification and this additional validation use logical read sampling. They do **not** prove every physical magnetic sector or magnetic domain independently, and they do not establish the state of remapped, hidden, or firmware-inaccessible areas. Stage 9A does not perform aggressive forensic recovery.

## 5. Interpret reports

Successful execution writes:

```text
hardware-validation/<timestamp>-hdd-<stable-id>.json
hardware-validation/<timestamp>-hdd-<stable-id>.md
```

`PASS` requires all of:

- identity preserved through post-test profiling;
- VYPER `final_status` and verifier status `VERIFIED`;
- selected `HDD_OVERWRITE` pathway;
- a successful sanitization certificate claim;
- valid and mutually bound evidence/certificate hashes;
- no filesystem or `blkid` signature detected;
- beginning, middle, and end samples matching the zero pattern.

A failed VYPER job produces `FAIL`. A verified product result with inconsistent or incomplete independent checks produces `INCONCLUSIVE`, not a false pass.

The permitted successful statement is:

> Known test data is no longer accessible through the logical block interface and sampled regions match the expected overwrite pattern.

Do not state that every magnetic domain is proven erased.

## Mock examples

The repository includes explicitly non-hardware examples at:

- `tests/fixtures/hardware_validation/sample_hdd_validation.json`
- `tests/fixtures/hardware_validation/sample_hdd_validation.md`

They demonstrate report shape only and are not physical validation evidence.
