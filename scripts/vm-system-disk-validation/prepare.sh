#!/bin/sh
set -eu

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then
  echo "Usage: $0 VM_VALIDATION_MANIFEST [--allow-destructive-vm-test]" >&2
  exit 2
fi

manifest=$1
mode=${2:-dry-run}
export VYPER_VM_VALIDATION=1

if [ "$mode" = "dry-run" ]; then
  exec sudo --preserve-env=VYPER_VM_VALIDATION vyper system-disk prepare --dry-run --vm-validation-manifest "$manifest"
fi

if [ "$mode" != "--allow-destructive-vm-test" ]; then
  echo "Unknown mode. Destructive validation requires the exact --allow-destructive-vm-test flag." >&2
  exit 2
fi

echo "WARNING: this path is destructive and is never enabled by this script alone."
echo "The manifest must also contain destructive_test_enabled=true and all boot-time gates must pass."
exec sudo --preserve-env=VYPER_VM_VALIDATION vyper system-disk prepare --authorize-system-disk \
  --vm-validation-manifest "$manifest" --allow-destructive-vm-test
