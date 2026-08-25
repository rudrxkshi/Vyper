#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 BOOT_MANIFEST INITRAMFS_IMAGE" >&2
  exit 2
fi

manifest=$1
initramfs=$2
test -f "$manifest"
test -f "$initramfs"

echo "Boot self-test (expected to PASS only inside the temporary VYPER boot environment):"
vyper system-disk boot-self-test
echo "Initramfs SHA-256:"
sha256sum "$initramfs"
echo "Required initramfs entries:"
lsinitramfs "$initramfs" | grep -E 'boot_console|boot_sanitize|agent.py|python|lsblk|hdparm|nvme'
echo "Manifest:"
python3 -m json.tool "$manifest"
