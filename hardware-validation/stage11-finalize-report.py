from __future__ import annotations

import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "stage11-postwipe-evidence" / "20260825T152038Z-system-disk-vm.json"
RESULT = ROOT / "stage11-postwipe-evidence" / "4edb1d85-ba87-4ee2-90d6-48808f00eaa6.result.json"
LOG = ROOT / "stage11-postwipe-evidence" / "4edb1d85-ba87-4ee2-90d6-48808f00eaa6.validation.jsonl"
OUT_JSON = ROOT / "20260825T152038Z-system-disk-vm-destructive.json"
OUT_MD = ROOT / "20260825T152038Z-system-disk-vm-destructive.md"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


report = json.loads(SOURCE.read_text(encoding="utf-8"))
result = json.loads(RESULT.read_text(encoding="utf-8"))
certificate = result["certificate"]
engine_evidence = result["engine_evidence"]
execution = result["execution"]
post_checks = {
    "inspection_vm": {
        "name": "vyper-stage11-inspector",
        "uuid": "3774cb52-a069-43b6-94f7-d72f450b5600",
        "target_device": "/dev/sdc",
        "evidence_device": "/dev/sdd",
    },
    "target_identity_match": True,
    "target_model": "VBOX HARDDISK",
    "target_serial": "VB374dbc03-ecfa2108",
    "target_size_bytes": 26843545600,
    "partition_table_detected": False,
    "filesystem_detected": False,
    "old_ubuntu_bootable": False,
    "sentinel_accessible": False,
    "target_mounted": False,
    "sample_method": "read-only cmp against /dev/zero; no harness dd",
    "samples": [
        {"region": "beginning", "offset": 0, "length": 4096, "all_zero": True},
        {"region": "middle", "offset": 13421772800, "length": 4096, "all_zero": True},
        {"region": "end", "offset": 26843541504, "length": 4096, "all_zero": True},
    ],
    "evidence_mount": {"device": "/dev/sdd", "mode": "ro,norecovery", "filesystem_uuid": "bd3e0b84-fe74-4f04-ad62-cf80c21eeee5"},
}
report.update({
    "virtual_disk_sanitization_validation": "PASS",
    "physical_media_validation": "NOT_APPLICABLE",
    "vm_identity": {
        "name": "vyper-stage11-disposable",
        "uuid": "de466510-ddae-4c3b-b1e1-adb5bb7482f1",
        "virtualbox_version": "7.2.14r174565",
        "system_disk_uuid": "374dbc03-9afd-41b3-ba0d-cb290821faec",
        "evidence_disk_uuid": "fd688823-928f-4327-942b-03873123731e",
    },
    "bytes_written": execution["metadata"]["bytes_written"],
    "post_checks": post_checks,
    "sentinel_status": {"accessible": False, "pre_wipe_sha256": "43eb0ca1aec5a29fa8325b6d44d20232377414f7afd8e78338f6458e96f7176a"},
    "warnings": [
        "VirtualBox validates virtual block-device behavior, not physical magnetic-media sanitization.",
        "The VYPER boot console completed evidence synchronization and requested shutdown, but VirtualBox remained running; the VM was powered off from the host only after the evidence disk was synchronized.",
    ],
    "archived_artifact_hashes": {
        "execution_result_sha256": digest(RESULT),
        "boot_validation_log_sha256": digest(LOG),
    },
})
OUT_JSON.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

(ROOT / "stage11-certificate.json").write_text(json.dumps(certificate, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(ROOT / "stage11-engine-evidence.json").write_text(json.dumps(engine_evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
(ROOT / "stage11-independent-post-checks.json").write_text(json.dumps(post_checks, indent=2, sort_keys=True) + "\n", encoding="utf-8")

OUT_MD.write_text(f"""# VYPER destructive VirtualBox system-disk validation

- Workflow validation: **{report['workflow_validation']}**
- Virtual-disk sanitization validation: **{report['virtual_disk_sanitization_validation']}**
- Physical-media validation: **{report['physical_media_validation']}**
- Boot job: `{report['boot_job_id']}`
- VM: `{report['vm_identity']['name']}` (`{report['vm_identity']['uuid']}`)
- Target: `{report['target_identity']['model']}` / `{report['target_identity']['serial_number']}`
- Selected pathway: `{report['selected_pathway']}`
- Bytes written: `{report['bytes_written']}`
- Verifier: `{report['verification']['status']}` ({report['verification']['samples_passed']}/{report['verification']['samples_checked']} samples passed)
- Evidence hash: `{report['evidence_hash']}`
- Certificate hash: `{report['certificate_hash']}`
- Old Ubuntu bootable: **No**
- Sentinel accessible: **No**

## Independent post-check

The exact wiped VDI was attached to a separate disposable inspector. It had no partition table or filesystem signature, was never mounted, and 4 KiB samples at the beginning, middle, and end compared entirely zero. The evidence VDI was mounted `ro,norecovery` and the retained result, validation log, and reports were archived.

## Scope and warning

This proves the VYPER product flow against a disposable VirtualBox virtual disk. Physical-media validation is not applicable, and no physical HDD, SATA SSD, or NVMe device was tested. The VYPER boot console synchronized evidence and requested shutdown, but VirtualBox did not exit; host power-off was used only after evidence synchronization.
""", encoding="utf-8")
