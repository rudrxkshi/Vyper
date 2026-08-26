# VYPER controlled physical-hardware validation runbook

This runbook covers the existing Stage 9A HDD, Stage 9B SATA SSD, and Stage 9C
NVMe SSD validation harnesses on Ubuntu. It is an operator procedure for one
explicitly selected disposable device. Physical validation has not yet been
performed, so every run is evidence-producing qualification work, not a
production sanitization claim.

> **Destructive boundary:** plan commands are read-only. Commands containing
> `prepare ... --execute` reformat the selected device. Validation commands
> containing `--execute` irreversibly sanitize it. Never copy a device path from
> this document without reconciling it against the physical label and current
> topology. Never automate or pipe the confirmation response.

## Roles, workspace, and evidence handling

Use two people where practical: an operator types commands and a witness verifies
the physical label, topology, plan, and confirmation phrase. Record the test ID,
date/time, host asset, operator, witness, drive manufacturer/model/serial/WWN,
physical connection, and the statement that all data on the drive may be lost.

Create a private capture directory before connecting or selecting the drive:

```bash
umask 077
mkdir -p "$PWD/hardware-validation/capture"
date --iso-8601=seconds | tee "$PWD/hardware-validation/capture/session-start.txt"
vyper version | tee "$PWD/hardware-validation/capture/vyper-version.txt"
sudo vyper status | tee "$PWD/hardware-validation/capture/vyper-status.txt"
sudo vyper diagnose --json | tee "$PWD/hardware-validation/capture/vyper-diagnose.json"
```

Do not place an ATA password, API key, enrollment token, or other credential in
notes, filenames, command lines, transcripts, reports, or archives.

## Common read-only preflight

Run these commands before choosing a device and save their output:

```bash
findmnt --noheadings --output SOURCE,TARGET --target / | tee "$PWD/hardware-validation/capture/os-mounts.txt"
findmnt --noheadings --output SOURCE,TARGET --target /boot 2>/dev/null | tee -a "$PWD/hardware-validation/capture/os-mounts.txt"
findmnt --noheadings --output SOURCE,TARGET --target /boot/efi 2>/dev/null | tee -a "$PWD/hardware-validation/capture/os-mounts.txt"
swapon --show --output NAME,TYPE,SIZE,USED,PRIO | tee "$PWD/hardware-validation/capture/swap.txt"
lsblk --bytes --paths --tree --output NAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,ROTA,TRAN,FSTYPE,MOUNTPOINTS | tee "$PWD/hardware-validation/capture/lsblk-before.txt"
sudo blkid | tee "$PWD/hardware-validation/capture/blkid-before.txt"
cat /proc/mdstat | tee "$PWD/hardware-validation/capture/mdstat-before.txt"
sudo pvs --noheadings 2>/dev/null | tee "$PWD/hardware-validation/capture/lvm-pvs-before.txt"
sudo dmsetup ls --tree 2>/dev/null | tee "$PWD/hardware-validation/capture/dm-before.txt"
```

If a utility is intentionally unavailable, record that fact. Do not interpret a
failed or incomplete safety query as “nothing found”; unknown safety state is an
abort condition.

Confirm the device is disposable using evidence independent of `/dev` naming:

1. Read the physical manufacturer, model, serial, WWN/EUI/NGUID, and capacity.
2. Match those fields to the test inventory or destruction authorization.
3. Confirm the inventory explicitly permits irreversible loss of all data.
4. Have the witness compare the label against VYPER and `udevadm`/controller
   output. A path such as `/dev/sdb` or `/dev/nvme0n1` is never identity.
5. Physically disconnect unrelated removable test drives when practical.

Confirm it is not the OS disk by comparing the selected device and all parents
and children against `findmnt`, swap, mdraid, LVM, and device-mapper output.
Inspect the exact candidate with:

```bash
lsblk --bytes --paths --tree --output NAME,PATH,PKNAME,TYPE,SIZE,MODEL,SERIAL,WWN,ROTA,TRAN,FSTYPE,MOUNTPOINTS /dev/EXACT_DEVICE
udevadm info --query=property --name /dev/EXACT_DEVICE
findmnt --source /dev/EXACT_DEVICE
```

Stop if the device, a partition, a parent, or a dependent mapping supplies `/`,
`/boot`, `/boot/efi`, swap, mdraid, LVM, device-mapper, multipath, or any mount.
Do not merely unmount an unexpectedly active device and continue; investigate
why it was active and restart the entire preflight.

## A. Rotational HDD — Stage 9A

### Preflight and identity

Replace `/dev/sdX` only after physical-label reconciliation:

```bash
lsblk --bytes --paths --tree --output NAME,PATH,PKNAME,TYPE,SIZE,MODEL,SERIAL,WWN,ROTA,TRAN,FSTYPE,MOUNTPOINTS /dev/sdX
udevadm info --query=property --name /dev/sdX
sudo smartctl -i /dev/sdX
sudo vyper validate-hardware hdd --device /dev/sdX
```

The plan must identify a whole, non-system, unmounted rotational HDD. Require
`rotational: true`, the expected model and capacity, and a stable serial or WWN.
Compare the serial/WWN suffix used by the displayed confirmation phrase with the
physical label. Stop for USB bridge identity ambiguity, missing stable identity,
unknown capacity/topology, any partition mount, or any changed value.

### Prepare controlled test data

Review preparation without changing the disk:

```bash
sudo vyper validate-hardware hdd prepare --device /dev/sdX
```

Only after operator and witness sign the plan, create the small synthetic ext4
dataset. This command is destructive and requires the exact displayed
`PREPARE <identity-suffix>` response:

```bash
sudo vyper validate-hardware hdd prepare --device /dev/sdX --execute
```

Capture the generated `*-hdd-*-test-data.json` manifest, filesystem UUID, file
names, sizes, and SHA-256 hashes. Confirm preparation reports a successful
unmount. Re-run common preflight and the HDD plan; compare identity and size to
the signed plan.

### Review policy and execute

The fresh plan must select `HDD_OVERWRITE`; no other pathway is acceptable.
Record the plan transcript before proceeding. Then run manually:

```bash
sudo vyper validate-hardware hdd --device /dev/sdX --execute
```

At `FINAL DEVICE IDENTITY`, compare model, serial/WWN, capacity, rotational
classification, mounts, and system state again. Type the exact displayed
`ERASE <identity-suffix>` only when both operator and witness agree. Do not
disconnect, suspend, reboot, or power off while the durable job is active.

### Capture and post-check

Preserve the durable job ID, state/progress history, selected pathway,
verification, evidence hash, certificate hash, final status, and both generated
reports. The harness performs `lsblk`, `blkid -p`, `file -s`, and 4 KiB logical
samples at the beginning, middle, and end. Independently capture afterward:

```bash
lsblk --bytes --paths --tree --output NAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,ROTA,FSTYPE,MOUNTPOINTS /dev/sdX
sudo blkid -p /dev/sdX
sudo file -s /dev/sdX
udevadm info --query=property --name /dev/sdX
```

For `HDD_OVERWRITE`, zero-pattern post-samples are logical verification only.
They do not independently prove every magnetic domain, hidden area, or remapped
sector. Any non-zero required sample, old filesystem signature, identity change,
failed probe, invalid evidence/certificate binding, or status other than the
documented PASS criteria is not a PASS. Do not rerun automatically.

## B. SATA SSD — Stage 9B

### Preflight and identity

Direct motherboard/HBA SATA attachment is preferred. Avoid USB-to-SATA bridges;
continue through a bridge only when the harness positively proves ATA
pass-through and every identity/capability field remains authoritative.

```bash
lsblk --bytes --paths --tree --output NAME,PATH,PKNAME,TYPE,SIZE,MODEL,SERIAL,WWN,ROTA,TRAN,FSTYPE,MOUNTPOINTS /dev/sdX
udevadm info --query=property --name /dev/sdX
sudo smartctl -i /dev/sdX
sudo hdparm -I /dev/sdX
sudo vyper validate-hardware sata-ssd --device /dev/sdX
```

Require the expected model, serial/WWN, capacity, `rotational: false`, SATA/ATA
classification, and no system/mount/dependency state. In `hdparm -I` and the
VYPER plan require ATA Security supported, Secure Erase supported, and
`frozen: false`. Enhanced Secure Erase availability is informative and does not
authorize a pathway substitution.

If frozen, stop. The harness does not automatically suspend, hot-plug,
power-cycle, or otherwise unfreeze a drive. Do not improvise an unfreeze action
during this run; record the condition and reschedule under a separately reviewed
hardware procedure.

### Prepare controlled test data

```bash
sudo vyper validate-hardware sata-ssd prepare --device /dev/sdX
```

After witnessed review, the following destructive command creates and unmounts
the small synthetic dataset and requires exact `PREPARE <identity-suffix>`:

```bash
sudo vyper validate-hardware sata-ssd prepare --device /dev/sdX --execute
```

Archive the `*-sata-ssd-*-test-data.json` manifest and its UUID/file hashes.
Re-run preflight, `hdparm -I`, and the SATA plan. Stop if ATA Security became
frozen, any identity/capability changed, or unmount is not proven.

### Review policy and execute

The plan must select exactly `ATA_ERASE`. There is no HDD-overwrite fallback and
no implied SATA crypto-erase support. Run manually:

```bash
sudo vyper validate-hardware sata-ssd --device /dev/sdX --execute
```

Verify the redisplayed identity and type the exact `ERASE <identity-suffix>`.
When prompted, enter the transient ATA password through hidden terminal input;
do not record it. Keep power stable during the indeterminate firmware operation.

### Capture and post-check

Archive the job lifecycle, `ATA_ERASE` policy, command-completion metadata,
verification, evidence/certificate hashes and binding, post-erase ATA Security
state, and JSON/Markdown reports. Capture independent read-only state:

```bash
sudo hdparm -I /dev/sdX
sudo smartctl -i /dev/sdX
lsblk --bytes --paths --tree --output NAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,ROTA,FSTYPE,MOUNTPOINTS /dev/sdX
sudo blkid -p /dev/sdX
sudo file -s /dev/sdX
udevadm info --query=property --name /dev/sdX
```

PASS requires the documented VYPER verification and integrity conditions, erase
completion, ATA Security disabled and unfrozen afterward, controller access, and
no contradictory old filesystem evidence. Logical reads cannot prove every NAND
cell, spare block, remapped block, or over-provisioned region. Any contradiction
is FAIL or INCONCLUSIVE according to the report; do not automatically retry.

## C. NVMe SSD — Stage 9C/9C.1

### Preflight, identity, and controller scope

Select an explicit namespace, never a controller, partition, wildcard, or
auto-selected device:

```bash
sudo nvme list
lsblk --bytes --paths --tree --output NAME,PATH,PKNAME,TYPE,SIZE,MODEL,SERIAL,WWN,ROTA,TRAN,FSTYPE,MOUNTPOINTS /dev/nvmeXnY
udevadm info --query=property --name /dev/nvmeXnY
sudo nvme id-ns /dev/nvmeXnY --output-format=json
sudo nvme list-subsys /dev/nvmeXnY
sudo vyper validate-hardware nvme --device /dev/nvmeXnY
```

Use the plan—not string chopping—to establish namespace-to-controller ownership.
It must show all of the following with no blocker:

```text
Requested namespace: /dev/nvmeXnY
Resolved controller: /dev/nvmeX
Sanitize scope: controller
Controller namespaces:
  - /dev/nvmeXnY
Sanitize target: /dev/nvmeX
Physical execution eligibility: ELIGIBLE
```

Run controller identify only against the controller printed by the plan:

```bash
sudo nvme id-ctrl /dev/nvmeX --output-format=json
sudo nvme sanitize-log /dev/nvmeX --output-format=json
```

Reconcile namespace NGUID, EUI-64, UUID if exposed, namespace ID, and capacity.
Separately reconcile controller path, serial, model, firmware, PCI/sysfs
identity, and transport. SANICAP must be known from controller identify data and
must support the exact policy-selected method. Require exactly one listed
controller namespace. If the mapping is ambiguous, the controller is missing,
more than one namespace exists, or any controller namespace is mounted,
system-associated, swap, LVM, mdraid, device-mapper, multipath, held, or unknown,
do not execute.

### Prepare controlled test data

```bash
sudo vyper validate-hardware nvme prepare --device /dev/nvmeXnY
```

After witnessed review, this destructive command creates the small synthetic
dataset and requires exact `PREPARE <identity-suffix>`:

```bash
sudo vyper validate-hardware nvme prepare --device /dev/nvmeXnY --execute
```

Archive the `*-nvme-*-test-data.json` manifest and hashes. Re-run common
preflight and the NVMe plan. The same namespace must resolve to the same
controller, exactly one safe namespace must remain, and all identity, capacity,
topology, SANICAP, policy, and target fields must be unchanged.

### Review policy and execute

Match the selected method to controller SANICAP and the fixed SANACT mapping:

| Selected policy/pathway | Required SANACT |
|---|---:|
| `CRYPTO_ERASE` | 4 |
| `BLOCK_ERASE` | 2 |
| `NVME_OVERWRITE` / `OVERWRITE` | 3 |

No fallback or substitution is permitted. Execute only when the plan says
`ELIGIBLE` and the sanitize target is the proven controller:

```bash
sudo vyper validate-hardware nvme --device /dev/nvmeXnY --execute
```

At confirmation, recheck both identity levels, namespace count, SANICAP,
selected method/SANACT, controller target, mounts, system state, and holders.
Type exact `ERASE <identity-suffix>` only after witnessed agreement. Do not
disconnect, reset, suspend, reboot, or power-cycle the controller while its
sanitize state is unresolved.

### Capture and post-check

Preserve requested namespace, resolved controller, controller namespace list,
sanitize target/scope, selected/effective method and SANACT, durable lifecycle,
raw and parsed SSTAT timeline, submission result, controller completion,
verification, evidence/certificate hashes and binding, and both reports.

Using the controller and namespace printed by the report, capture:

```bash
sudo nvme id-ctrl /dev/nvmeX --output-format=json
sudo nvme id-ns /dev/nvmeXnY --output-format=json
sudo nvme sanitize-log /dev/nvmeX --output-format=json
lsblk --bytes --paths --tree --output NAME,PATH,TYPE,SIZE,MODEL,SERIAL,FSTYPE,MOUNTPOINTS /dev/nvmeXnY
sudo blkid -p /dev/nvmeXnY
sudo file -s /dev/nvmeXnY
udevadm info --query=property --name /dev/nvmeXnY
```

Command acceptance alone is not PASS. Require structured controller SSTAT
`COMPLETED`, VYPER final and verifier status `VERIFIED`, supported SANICAP,
expected SANACT, stable namespace/controller identity, valid bound evidence and
certificate, and no contradictory critical probe. `IN_PROGRESS`, missing or
malformed SSTAT, bit 8 alone, unavailable probes, or temporary disappearance
cannot produce PASS. Do not resubmit sanitize automatically.

## Archive and closeout

For every device class, retain:

- signed preflight and physical-label/custody record;
- complete before/after command output and operator transcript;
- preparation manifest, if preparation was executed;
- VYPER JSON and Markdown validation reports;
- durable job ID and lifecycle/progress or SSTAT timeline;
- policy decision, execution metadata, verification result, evidence record,
  certificate, evidence hash, certificate hash, and binding result;
- independent post-check output and photographs of the physical label/connection;
- operator/witness conclusion and every limitation or anomaly.

Check report files before archiving:

```bash
find "$PWD/hardware-validation" -maxdepth 2 -type f ! -name archive-sha256.txt -print0 | sort -z | xargs -0 sha256sum > "$PWD/hardware-validation/capture/archive-sha256.txt"
tar --create --gzip --file "vyper-physical-validation-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" hardware-validation
```

Store the archive according to the organization’s evidence-retention policy.
If evidence/report hashes disagree, identity differs, or required evidence is
missing, label the run INCONCLUSIVE, preserve everything, and investigate. Never
rerun a destructive operation merely to obtain a cleaner report.

## Exact abort conditions

Stop before typing PREPARE or ERASE, or stop without resubmitting if already
running, when any of these applies:

- physical label, model, serial, WWN, NGUID, EUI-64, UUID, or namespace ID is
  wrong, missing when required, ambiguous, or changed;
- capacity changed or does not match the authorized disposable asset;
- the device or any controller namespace is system-associated, mounted, swap,
  held, or participates in LVM, mdraid, device-mapper, or multipath;
- classification, topology, mount, system, dependency, capability, controller,
  or identity state is unknown;
- the selected policy/pathway is unexpected or its required capability is not
  positively supported;
- HDD is not positively rotational or lacks stable serial/WWN;
- SATA SSD is frozen, lacks Secure Erase, or ATA pass-through is unproven;
- NVMe namespace/controller relation is ambiguous, controller target is absent,
  SANICAP is unknown/unsupported, or the controller exposes multiple namespaces;
- the fresh post-confirmation profile differs from the reviewed plan;
- preparation did not unmount cleanly;
- evidence integrity, certificate integrity, evidence/certificate binding,
  successful claim, verifier state, or report fields disagree;
- the operator or witness is uncertain for any reason.

If the device disappears during an active controller operation, preserve power
and observe the existing job/status behavior. Do not issue a second destructive
command. An unresolved or unprovable terminal state is INCONCLUSIVE or FAIL, not
permission to retry.

---

# Printable one-page checklist

A standalone print-oriented copy is available at
[`PHYSICAL_HARDWARE_CHECKLIST.md`](PHYSICAL_HARDWARE_CHECKLIST.md).

**Test ID:** __________  **Date/time:** __________  **Operator:** __________
**Witness:** __________  **Host:** __________  **Class:** HDD / SATA / NVMe

**Authorized device:** Model __________  Serial/WWN/NGUID __________
Capacity __________  Physical port/connection __________

## Before connecting or selecting

- [ ] Written authorization confirms the device is disposable and all data may be lost.
- [ ] Physical label photographed; model, stable ID, and capacity recorded.
- [ ] VYPER version/status/diagnose and before-state topology captured.
- [ ] OS, boot, EFI, swap, mdraid, LVM, device-mapper, multipath identified.
- [ ] Candidate and every child/parent/controller namespace are non-system and unmounted.
- [ ] Identity, capacity, topology, capability, and holder state are fully known.

## Class gate

- [ ] **HDD:** rotational=true; expected model/size; stable serial or WWN; plan selects `HDD_OVERWRITE`.
- [ ] **SATA:** direct SATA preferred; rotational=false; ATA/SATA identified; Secure Erase supported; not frozen; plan selects `ATA_ERASE`; no automatic unfreeze.
- [ ] **NVMe:** namespace→controller proven; controller target shown; exactly one safe namespace; controller SANICAP known/supports method; no mount/system/swap/holder across controller; plan says `ELIGIBLE`.

## Prepare and re-plan

- [ ] Read-only `prepare` plan reviewed by operator and witness.
- [ ] If used, exact PREPARE phrase typed manually; manifest/hashes saved; unmount proven.
- [ ] Full preflight and validation plan repeated after preparation.
- [ ] Model, stable identity, size, classification, policy, and scope are unchanged.

## Execute

- [ ] Correct explicit device path entered; no wildcard, partition, or auto-selection.
- [ ] Final identity and safety display matches signed plan.
- [ ] Exact ERASE phrase typed manually; no credential recorded.
- [ ] Power remains stable; no unplug, reset, suspend, reboot, or automatic retry.

## Evidence and closeout

- [ ] Job ID/lifecycle, policy, execution, verification, evidence, certificate captured.
- [ ] JSON/Markdown report and preparation manifest archived.
- [ ] Independent read-only post-checks captured.
- [ ] Evidence hash, certificate hash, binding, identity, method, and conclusion agree.
- [ ] HDD zeros treated only as logical samples; SSD/NVMe claims respect controller/firmware limits.
- [ ] Archive SHA-256 inventory generated; operator/witness conclusion signed.

## DO NOT CONTINUE if any box applies

- [ ] Wrong or changed model/serial/stable identity
- [ ] System disk, mounted device, swap, holder, RAID/LVM/device-mapper/multipath
- [ ] Identity or size changed
- [ ] Safety state unknown
- [ ] Unsupported or unknown capability/pathway
- [ ] SATA frozen or Secure Erase unsupported
- [ ] NVMe controller scope ambiguous or controller target missing
- [ ] Multiple NVMe namespaces
- [ ] Evidence, certificate, verification, or report mismatch
- [ ] Operator or witness uncertainty

**Conclusion:** PASS / FAIL / INCONCLUSIVE  **Archive:** ____________________

**Operator signature:** __________________  **Witness:** __________________
