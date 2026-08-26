#!/bin/sh
set -eu

if [ "$#" -lt 4 ]; then
  echo "Usage: $0 OUTPUT.json TARGET_MODEL TARGET_SERIAL TARGET_SIZE_BYTES [EVIDENCE_MODEL EVIDENCE_SERIAL EVIDENCE_SIZE_BYTES]" >&2
  exit 2
fi

output=$1
target_model=$2
target_serial=$3
target_size=$4
shift 4

case "$target_size" in *[!0-9]*|'') echo "TARGET_SIZE_BYTES must be a positive integer" >&2; exit 2;; esac
[ "$target_size" -gt 0 ] || { echo "TARGET_SIZE_BYTES must be a positive integer" >&2; exit 2; }

python3 - "$output" "$target_model" "$target_serial" "$target_size" "$@" <<'PY'
import json, pathlib, sys
output, model, serial, size, *evidence = sys.argv[1:]
payload = {
    "validation_mode": "virtualbox_system_disk",
    "allowed_target_identity": {"device_type": "HDD", "model": model, "serial_number": serial, "size_bytes": int(size)},
    "destructive_test_enabled": False,
}
if evidence:
    if len(evidence) != 3:
        raise SystemExit("Evidence identity requires model, serial, and size")
    payload["evidence_disk_identity"] = {"model": evidence[0], "serial_number": evidence[1], "size_bytes": int(evidence[2])}
path = pathlib.Path(output)
path.parent.mkdir(parents=True, exist_ok=True)
path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
path.chmod(0o600)
print(path)
PY

echo "Created dry-run-only VM authorization manifest. Review every identity field before preparation."
