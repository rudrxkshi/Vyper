# Deterministic VirtualBox demo

Run this only in a disposable Ubuntu/Debian x86_64 VM snapshot. The host’s physical disks must not be passed through. Confirm the target by VM controller/port, VYPER model/serial/capacity, and `/dev/disk/by-id`; never rely on `/dev/sdb` alone.

## Scenario 1: disposable 5 GiB secondary HDD-like disk

1. Power off the VM, create a new 5 GiB dynamically allocated VDI, attach it as the second virtual SATA disk, and take a snapshot.
2. Boot the VM and verify the new disk is exactly 5 GiB and is not the root disk.
3. Partition and format only that new virtual disk, mount it, create several non-sensitive sample files, and record their SHA-256 checksums.
4. Unmount it and confirm no swap, LVM, RAID, or holders use it.
5. Open VYPER Local Console and show discovery, model/serial/capacity, non-system status, and the policy-selected `HDD_OVERWRITE` method.
6. Reconfirm the disposable VM identity, approve the destructive job, and show real measured byte progress. This is the only planned real overwrite demonstration, and it is confined to the disposable VDI.
7. Show `VERIFIED`, method-specific sample verification, evidence hash, outcome kind, and successful certificate claim.
8. Show the central agent’s outbound synchronization and matching local/central IDs.
9. Confirm the virtual disk no longer exposes the test filesystem and a read-only mount fails. Restore/delete the VM snapshot and VDI after the presentation.

Keep a second snapshot available so the demo can be repeated deterministically. Never attach a host raw disk, USB drive, shared production volume, or VirtualBox physical-disk mapping.

## Scenario 2: system-disk boot flow

The current Windows development host cannot build or boot the Ubuntu/Debian host-specific initramfs. Demonstrate this scenario as explicitly labeled **DRY-RUN / ISOLATED RESULT**, using a disposable VM or the repository fixture:

1. Show normal-mode rejection of the active system disk.
2. Run `vyper system-disk prepare --dry-run` with handoff application disabled in the fixture.
3. Show the expiring HMAC-protected manifest and one-shot GRUB configuration.
4. Show path-independent identity matching, topology validation, and the fresh confirmation screen.
5. Run the dry-run boot workflow and show zero destructive calls and `INCONCLUSIVE`, as expected for dry run.
6. Separately show a mocked isolated `VERIFIED` evidence shape, clearly labeled as a test fixture—not a real system-disk wipe.

VirtualBox does not expose representative ATA/NVMe firmware sanitize behavior. Do not present a VirtualBox command result as proof of ATA Secure Erase or NVMe sanitize support.

