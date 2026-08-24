# Install VYPER on Linux

Stage 5 supports Ubuntu/Debian x86_64 with Python 3.11 or newer and systemd.

1. Download `vyper-local-console-linux-x86_64.tar.gz` and its checksum.
2. Run `sha256sum -c checksums.txt`.
3. Extract the archive.
4. Run `sudo ./install.sh`.
5. Run `sudo vyper enroll`; the enrollment token is read without echo.
6. Run `vyper open` to open `http://127.0.0.1:8787`.

The installer checks for `lsblk`, `hdparm`, `nvme`, and `smartctl`. It does not
silently install OS packages. Install only the reported missing Ubuntu/Debian
packages (`util-linux`, `hdparm`, `nvme-cli`, or `smartmontools`) and retry.

Files are installed under `/opt/vyper`, configuration and credentials under
`/etc/vyper`, durable state under `/var/lib/vyper`, and logs under
`/var/log/vyper`. Mutable state is never stored in `/opt/vyper`.
