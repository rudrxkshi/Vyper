# Install VYPER on Linux

Stage 5 supports Ubuntu/Debian x86_64 with Python 3.11 or newer and systemd.

1. Download `vyper-local-console-linux-x86_64-1.0.0-rc1.tar.gz` and its checksum.
2. Run `sha256sum -c checksums.txt`.
3. Extract the archive.
4. Run `sudo ./install.sh`.
5. Run `sudo vyper enroll`; the enrollment token is read without echo.
6. As the non-root desktop user, launch **VYPER Local Console** from the
   application menu or run `vyper open`.

The installer checks for `lsblk`, `hdparm`, `nvme`, and `smartctl`. It does not
silently install OS packages. Install only the reported missing Ubuntu/Debian
packages (`util-linux`, `hdparm`, `nvme-cli`, or `smartmontools`) and retry.

Files are installed under `/opt/vyper`, configuration and credentials under
`/etc/vyper`, durable state under `/var/lib/vyper`, and logs under
`/var/log/vyper`. Mutable state is never stored in `/opt/vyper`.

The native Tauri GUI is installed under `/opt/vyper/gui`. It embeds the same
local-mode dashboard and calls the loopback API on port 8765. The existing
port-8787 static console remains available as a compatibility fallback. See
`DESKTOP_GUI.md` for development and manual validation instructions.
