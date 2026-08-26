# Boot sanitize environment

Stage 7 builds a minimal Ubuntu/Debian initramfs with the installed VYPER Python runtime, device discovery, `hdparm`, `nvme-cli`, `lsblk`, `findmnt`, `swapon`, `pvs`, wired networking, CA certificates, and a small console entrypoint. The initramfs executes VYPER only when the kernel command line contains `vyper.mode=boot_sanitize`; otherwise the hook exits.

Build a host-specific image on a supported x86_64 Linux installation:

```console
$ sudo /opt/vyper/runtime/bin/python /opt/vyper/boot/build_boot_image.py --output-dir /opt/vyper/boot
```

The build uses the installed kernel and `mkinitramfs`, inspects the result with `lsinitramfs`, and refuses an artifact missing required components. It emits `manifest.json` and `checksums.txt` containing SHA-256 hashes. A deterministic `--fixture` build exists only for non-destructive CI; its manifest says `bootable: false`, and handoff refuses it.

At preparation time VYPER appends a deterministic, job-specific CPIO overlay containing the authenticated manifest, job state, MAC key, and active-job marker. An enrolled agent credential is included only for an explicitly central boot job. No ATA password, development database, source-control metadata, or general developer secret is built into the reusable image.

The manifest and replay/lifecycle state use canonical JSON and HMAC-SHA256. This provides authenticated integrity within the local-root trust boundary: an attacker who already controls root and can replace both the key and image is outside the prototype's protection. The image hash in the job and kernel/initramfs hashes in the image manifest are checked before handoff.

Boot safety inspection is read-only. It uses fixed argv calls without a shell and checks mounts, temporary root backing, swap, LVM membership, sysfs holders, active RAID/device-mapper/crypt/multipath types, and known filesystem membership signatures. Any tool failure or unparsable response means STOP.

The boot console shows the physical identity, capacity, interface, exact selected method, destructive warning, and requires `ERASE <last-eight-job-id-characters>`. Firmware operations remain indeterminate unless the existing pathway exposes trustworthy progress. After a terminal result the environment powers off and never automatically boots the erased OS.
