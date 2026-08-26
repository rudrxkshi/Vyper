# Boot handoff and recovery

VYPER supports GRUB2's one-shot `next_entry` mechanism on Ubuntu/Debian x86_64. Preparation adds a VYPER menu entry, regenerates GRUB configuration, disables active swap, and calls `grub-reboot "VYPER Boot Sanitize"`. It does not change GRUB's saved or default entry. The kernel command line includes `noresume`, preventing hibernation resume into the armed OS.

If the temporary environment fails before sanitization starts, the following boot falls back to the existing normal default. From the still-intact OS, inspect or cancel the job:

```console
$ sudo vyper system-disk status
$ sudo vyper system-disk cancel
```

Cancellation clears GRUB's `next_entry`. If command-line recovery is needed before reboot, run `sudo grub-editenv - unset next_entry`, then choose the normal OS in GRUB. Do not manually re-arm an expired job; prepare a new one.

Jobs expire and their nonce becomes consumed immediately before the native engine is called. A restart after that point never auto-repeats sanitization: the state becomes `INCONCLUSIVE` and requires a newly prepared job and another local confirmation. Power loss never produces `VERIFIED`. Firmware operations that may continue internally after a reset remain unknown unless the existing protocol evidence proves a terminal outcome.

Before handoff, VYPER invokes `swapoff --all`; the boot environment also refuses any target with active swap. If handoff preparation fails, VYPER reports the error and does not intentionally replace the normal default. Administrators should retain vendor boot/recovery access because a successful system-disk sanitization destroys the installed OS and its recovery partitions.

