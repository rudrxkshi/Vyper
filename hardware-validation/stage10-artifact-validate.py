from __future__ import annotations

import json
from pathlib import Path

from local_agent.vm_validation import validate_linux_boot_artifact


manifest = Path("/opt/vyper/boot/manifest.json")
listing = Path("/opt/vyper-stage10/hardware-validation/lsinitramfs.txt").read_text(encoding="utf-8")
report = validate_linux_boot_artifact(manifest, listing=listing)
required_markers = [
    "local_agent/boot_console.py",
    "local_agent/boot_sanitize.py",
    "local_agent/vm_validation.py",
    "agent/agent.py",
    "agent/evidence.py",
    "agent/certificate.py",
    "opt/vyper/runtime/bin/python",
    "usr/bin/python3",
    "usr/bin/python3.14",
    "usr/lib/python3.14/encodings/__init__.py",
    "usr/bin/lsblk",
    "usr/bin/findmnt",
    "usr/sbin/swapon",
    "usr/sbin/pvs",
    "usr/sbin/hdparm",
    "usr/sbin/nvme",
    "usr/bin/ip",
    "usr/bin/systemd-detect-virt",
    "usr/sbin/dhclient",
    "usr/bin/poweroff",
    "usr/bin/reboot",
]
lines = listing.splitlines()
report["required_component_paths"] = {
    marker: next((line for line in lines if line.endswith(marker)), None)
    for marker in required_markers
}
missing = [marker for marker, path in report["required_component_paths"].items() if path is None]
report["explicit_missing_components"] = missing
if missing:
    report["status"] = "FAIL"
    report["blockers"].append(f"Explicit component checks failed: {', '.join(missing)}")
print(json.dumps(report, indent=2, sort_keys=True))
raise SystemExit(0 if report["status"] == "PASS" else 1)
