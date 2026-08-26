# VirtualBox system-disk boot validation

This runbook validates VYPER's complete system-disk boot handoff in a disposable
VirtualBox VM:

```text
Windows development host
  -> VirtualBox
     -> Disk A: disposable Ubuntu/VYPER system disk
     -> Disk B: optional preformatted evidence/result disk
     -> temporary VYPER initramfs boot environment
```

Source may be edited from Windows or VS Code, but a bootable kernel/initramfs
must be built and inspected inside Ubuntu. Windows-built fixtures are
intentionally non-bootable. VirtualBox can validate application workflow and
virtual block-device behavior; it cannot support a physical-media firmware
sanitization claim.

> Never attach a host physical disk, raw host disk, shared VHD containing needed
> data, or production virtual disk to this workflow. Create new dynamically
> allocated VirtualBox disks specifically for this test. The scripts have no
> default target and never run `dd` or a sanitize command directly.

## Supported topology

Disk A contains disposable Ubuntu and VYPER. Disk B is optional for dry-run but
mandatory for the future destructive VM test. Disk B must be a different,
positively identified, preformatted filesystem that the temporary environment
can mount. The boot environment retains results in memory if Disk B is absent;
that fallback does not satisfy destructive eligibility.

Use VirtualBox's normal virtual-disk attachments, not raw-disk access. Enable
serial-number reporting for both disks and record their VirtualBox UUIDs,
models, serials, and sizes. Take a powered-off baseline snapshot for dry-run
recovery. Do not rely on a snapshot to recover evidence after an intentionally
destructive test; export Disk B results first.

## 1. Ubuntu preflight

Boot normally from Disk A and enter the repository checkout:

```bash
systemd-detect-virt
cat /sys/class/dmi/id/sys_vendor
cat /sys/class/dmi/id/product_name
uname -r
lsblk --bytes --paths --output NAME,PATH,TYPE,SIZE,MODEL,SERIAL,FSTYPE,MOUNTPOINTS
findmnt --target /
sudo vyper status
sudo vyper diagnose --json
```

Require `systemd-detect-virt` and DMI data to prove VirtualBox/Oracle. Record Disk
A's exact model `VBOX HARDDISK`, serial, and byte size. If Disk B is used, record
its different serial and size. A flag alone never proves disposability.

Format Disk B only while Ubuntu is running normally and only after its physical
VM identity has been independently checked. This runbook intentionally does not
provide a formatting command because filesystem creation is destructive and the
correct partitioning choice is environment-specific.

## 2. Build and validate the real boot artifact inside Ubuntu

Ensure the packaged initramfs hook and VYPER runtime are installed at their
normal Ubuntu paths. Build without `--fixture`:

```bash
sudo python3 packaging/boot/build_boot_image.py --output-dir /opt/vyper/boot
sudo lsinitramfs /opt/vyper/boot/initramfs.img | tee hardware-validation/lsinitramfs.txt
sha256sum /opt/vyper/boot/vmlinuz /opt/vyper/boot/initramfs.img | tee hardware-validation/boot-sha256.txt
python3 -m json.tool /opt/vyper/boot/manifest.json | tee hardware-validation/linux-boot-manifest.json
bash scripts/vm-system-disk-validation/verify-boot.sh /opt/vyper/boot/manifest.json /opt/vyper/boot/initramfs.img
```

The generated manifest must say:

```text
bootable: true
build_kind: ubuntu-debian-initramfs-tools
validated_with_lsinitramfs: true
kernel_version: <running Ubuntu kernel>
contains_agent_credentials: false
contains_operator_secrets: false
```

Archive the kernel version, kernel/initramfs SHA-256 values, boot environment
version, full `lsinitramfs` listing, included tools, Python runtime paths, and
manifest. Confirm `boot_console`, `boot_sanitize`, VYPER agent/evidence/
certificate modules, Python, `lsblk`, `findmnt`, `swapon`, `pvs`, `hdparm`,
`nvme`, networking, and shutdown tooling are present. A repository example at
`tests/fixtures/vm_system_disk/linux-initramfs-manifest.example.json` is
deliberately non-bootable and is not a substitute for this Ubuntu output.

## 3. Create the disposable-target authorization

Create a dry-run-only manifest using values copied from Ubuntu discovery:

```bash
bash scripts/vm-system-disk-validation/setup.sh \
  hardware-validation/vm-validation.json \
  'VBOX HARDDISK' 'DISK_A_EXACT_SERIAL' DISK_A_EXACT_SIZE_BYTES \
  'VBOX HARDDISK' 'DISK_B_EXACT_SERIAL' DISK_B_EXACT_SIZE_BYTES
python3 -m json.tool hardware-validation/vm-validation.json
```

The initial manifest contains `destructive_test_enabled: false`. Review it with
a witness. Model, serial, and size are all mandatory; a `/dev/sdX` path is not
authorization. Disk A and Disk B identities must differ.

## A. Complete dry-run boot test

First preview without applying GRUB state:

```bash
export VYPER_VM_VALIDATION=1
sudo --preserve-env=VYPER_VM_VALIDATION vyper system-disk prepare \
  --dry-run --vm-validation-manifest hardware-validation/vm-validation.json --no-apply
```

Then prepare the real one-shot handoff while keeping the engine dry-run:

```bash
bash scripts/vm-system-disk-validation/prepare.sh hardware-validation/vm-validation.json
sudo vyper system-disk status
sudo grub-editenv - list
```

Record the current saved/default entry, generated `VYPER Boot Sanitize` entry,
and `next_entry`. The saved default must remain unchanged. Reboot only after the
boot job says `AWAITING_REBOOT`:

```bash
sudo vyper system-disk reboot --confirm-reboot
```

The temporary environment automatically runs the read-only boot self-test,
validates the HMAC-authenticated boot job, discovers Disk A by stable identity,
proves it is not the active temporary root, checks mounts/swap/LVM/RAID/holders,
revalidates VirtualBox and the disposable manifest, and asks for fresh
`ERASE <boot-job-suffix>` confirmation. The confirmation is still required in
dry-run mode. Automated unit tests inject confirmation only through mocked
runtime calls; `VYPER_VM_VALIDATION=1` does not bypass or automate the live
prompt.

Dry-run invokes the existing VYPER engine with `dry_run=true`. It must not issue
a destructive command and must not return sanitization VERIFIED. Expected
lifecycle:

```text
PREPARING_BOOT -> AWAITING_REBOOT -> BOOT_ENVIRONMENT_STARTED
-> VALIDATING_TARGET -> WAITING_LOCAL_APPROVAL -> RUNNING -> VERIFYING
-> INCONCLUSIVE
```

The validation report may conclude:

```text
workflow_validation: PASS
sanitization_validation: NOT_EXECUTED
```

That means the boot workflow passed, not that disk sanitization was validated.
After the one-shot boot, the saved Ubuntu default remains unchanged and the next
normal boot returns to Ubuntu. Cancellation before reboot must clear `next_entry`:

```bash
sudo vyper system-disk cancel
sudo grub-editenv - list
```

Expired or tampered jobs must refuse. If the temporary boot fails, do not arm a
new job until the normal next boot and retained evidence are reviewed.

## Boot environment self-test

The command is read-only:

```bash
sudo vyper system-disk boot-self-test
```

It reports PASS/FAIL for Linux kernel, boot-mode marker, Python, VYPER imports,
`lsblk`, `hdparm`, `nvme`, networking, evidence/certificate modules, boot
manifest parser, HMAC key, writable results, and shutdown tooling. It is expected
to fail the boot-environment marker when invoked from normal Ubuntu; the
temporary environment runs it automatically and refuses the job if any required
item fails.

## B. Optional destructive virtual-disk test

This task does not execute this mode. Perform it only later, manually, against a
new disposable VM after a successful dry-run and evidence review.

All independent gates are mandatory:

1. VirtualBox proven by systemd and DMI.
2. Disk A model, serial, size, and stable identity match the signed manifest.
3. Disk A was the prepared VM system disk.
4. Temporary boot root is independent of Disk A.
5. Disk B is positively identified, different, and successfully mounted.
6. Manifest contains `destructive_test_enabled: true` after explicit review.
7. CLI includes `--allow-destructive-vm-test`.
8. Boot manifest, execution mode, topology, and target safety all validate.
9. Fresh confirmation is typed inside the boot environment.

Only after editing the reviewed manifest to enable the destructive test:

```bash
bash scripts/vm-system-disk-validation/prepare.sh \
  hardware-validation/vm-validation.json --allow-destructive-vm-test
sudo vyper system-disk reboot --confirm-reboot
```

For a rotational `VBOX HARDDISK`, policy must select `HDD_OVERWRITE` through
`boot_sanitize -> VYPERAgent -> verifier -> evidence -> certificate`. The
harness never invokes `dd`. VERIFIED is permitted only if the existing engine
verifier succeeds. Expected effects are loss of Disk A's Ubuntu filesystem and
inability to boot the old OS, with results retained on Disk B or centrally.

## C. Result collection

Preserve the authenticated boot manifest/state, boot validation JSONL log,
kernel and image hashes, GRUB handoff data, target/evidence identities, lifecycle,
engine result, evidence, certificate, offline outbox, and VM report:

```text
hardware-validation/<timestamp>-system-disk-vm.json
hardware-validation/<timestamp>-system-disk-vm.md
```

## Terminal status and shutdown semantics

`execution.raw_status` preserves the pathway/command-phase status captured before
verification. A raw value of `RUNNING` means the command phase completed and was
eligible for verification; it does not mean a terminal job is still active.
`execution.status` and `orchestration_terminal_status` are the user-facing terminal
view. `execution_status_semantics` labels raw evidence fields without rewriting the
integrity-protected evidence or certificate payloads.

Sanitization and machine shutdown are independent terminal dimensions. Reports use
`sanitization_status`, `shutdown_status`, `shutdown_method`, and `shutdown_warning`.
A post-result poweroff failure is an operational warning and does not downgrade a
previously valid `VERIFIED` sanitization result.

The report correlates `boot_job_id`, `local_job_id`, optional `central_job_id`,
`agent_id`, target identity, boot image hash, execution environment, evidence
hash, and certificate hash. Network loss must retain results offline. If Disk B
is missing in dry-run, the result truthfully remains
`RETAINED_IN_BOOT_MEMORY`.

From Ubuntu or an evidence mount, collect without touching Disk A:

```bash
bash scripts/vm-system-disk-validation/collect-results.sh \
  hardware-validation vyper-system-disk-validation.tar.gz
```

Logs record startup, kernel, manifest validation, discovery, identity/safety,
confirmation state, lifecycle, and upload state. ATA passwords, HMAC keys,
tokens, credentials, and operator secrets must never appear.

An illustrative, explicitly mocked command result is stored at
`tests/fixtures/vm_system_disk/boot-self-test.json`. It is not proof of an
Ubuntu boot. Archive the actual JSON emitted in the temporary boot environment
as part of every validation run.

## D. Recovery and independent inspection

For dry-run, power off and restore the baseline snapshot only after exporting
results. For a destructive test, do not attempt to boot Disk A as the old OS.
Power off the VM, detach Disk A, and attach it read-only to another disposable
inspection VM or recovery environment. Run:

```bash
lsblk -f
sudo blkid -p /dev/EXACT_INSPECTION_DISK
sudo file -s /dev/EXACT_INSPECTION_DISK
```

Record read-only beginning/middle/end logical samples using an independently
reviewed inspection tool. A virtual rotational HDD overwritten by the current
pathway may show zeros at sampled logical regions. This validates VYPER workflow
and VirtualBox block behavior, not physical-media firmware or magnetic domains.

For shutdown before reboot, absent confirmation, reboot/crash before execution,
crash during RUNNING, expiry, tampering, identity change, missing Disk B, or
network loss: preserve state and never infer VERIFIED. Nonce consumption prevents
automatic replay. Never resubmit a destructive operation merely to obtain a
cleaner result.
