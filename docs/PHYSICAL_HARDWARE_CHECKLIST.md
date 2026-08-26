# VYPER physical validation — printable checklist

**Test ID:** ______ **UTC:** ______ **Operator:** ______ **Witness:** ______
**Host:** ______ **Class:** HDD / SATA / NVMe **Device path:** ______
**Model:** ______ **Serial/WWN/NGUID:** ______ **Capacity:** ______

## Authorization and preflight

- [ ] Written authorization says this exact device is disposable; label/connection photographed.
- [ ] VYPER version, status, diagnose, `findmnt`, swap, `lsblk`, `blkid`, mdraid, LVM, and device-mapper output captured.
- [ ] Physical label matches model, stable identity, and capacity shown by VYPER and `udevadm`/controller tools.
- [ ] Device and every child, parent, dependency, or controller namespace are non-system, unmounted, and not swap/RAID/LVM/device-mapper/multipath.
- [ ] Identity, capacity, topology, capability, mount, system, and holder state are fully known.

## Required class gate

- [ ] **HDD:** rotational=true; stable serial/WWN; expected capacity; plan selects `HDD_OVERWRITE`.
- [ ] **SATA:** direct SATA preferred; rotational=false; Secure Erase supported; not frozen; plan selects `ATA_ERASE`; no automatic unfreeze.
- [ ] **NVMe:** namespace→controller proven; controller target shown; exactly one safe namespace; controller SANICAP supports selected method; no controller-wide use; plan says `ELIGIBLE`.

## Prepare and execute

- [ ] Read-only plan reviewed and saved before each `--execute` command.
- [ ] If preparation is used: exact PREPARE phrase typed manually; manifest/hashes saved; unmount proven.
- [ ] Full preflight and plan repeated after preparation; identity, size, classification, policy, capability, and scope unchanged.
- [ ] Final identity display witnessed; exact ERASE phrase typed manually; no secret recorded.
- [ ] Stable power maintained; no unplug, reset, suspend, reboot, or automatic destructive retry.

## Evidence and closeout

- [ ] Job ID/lifecycle, policy, execution, verification, evidence, and certificate captured.
- [ ] JSON/Markdown report, preparation manifest, and independent read-only post-checks archived.
- [ ] Evidence hash, certificate hash, binding, identity, method/SANACT, and conclusion agree.
- [ ] HDD zero samples treated only as logical evidence; SSD/NVMe claims retain controller/firmware limitations.
- [ ] Archive SHA-256 inventory generated; operator and witness sign the conclusion.

## DO NOT CONTINUE

- [ ] Wrong/missing/changed model, serial, stable identity, or size
- [ ] System disk, mount, swap, holder, RAID, LVM, device-mapper, or multipath
- [ ] Unknown safety, identity, topology, controller, or capability state
- [ ] Unsupported/unexpected policy or capability; SATA frozen; Secure Erase unsupported
- [ ] NVMe scope ambiguous, controller target absent, SANICAP unknown, or multiple namespaces
- [ ] Preparation not cleanly unmounted; evidence/certificate/verification/report mismatch
- [ ] Operator or witness uncertainty

**Conclusion:** PASS / FAIL / INCONCLUSIVE **Archive:** __________________

**Operator signature:** __________________ **Witness:** __________________
