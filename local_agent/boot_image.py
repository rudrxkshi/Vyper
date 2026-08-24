from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .boot_sanitize import BOOT_ENVIRONMENT_VERSION, sha256_file


REQUIRED_IMAGE_MARKERS = ("hdparm", "nvme", "lsblk", "findmnt", "swapon", "pvs", "local_agent", "python")


def _run(command: list[str], *, timeout: int = 300) -> subprocess.CompletedProcess:
	return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout)


def _secure_boot_compatible(kernel: Path) -> bool:
	tool = shutil.which("sbverify")
	if not tool:
		return False
	result = _run([tool, "--list", str(kernel)], timeout=30)
	return result.returncode == 0 and "signature" in result.stdout.lower()


def write_manifest(output_dir: Path, *, kernel: Path, initramfs: Path, bootable: bool,
	secure_boot_compatible: bool, build_kind: str) -> Path:
	build_epoch = int(os.getenv("SOURCE_DATE_EPOCH", "1787529600"))
	payload: dict[str, Any] = {
		"product": "VYPER Boot Sanitize Environment", "version": BOOT_ENVIRONMENT_VERSION,
		"platform": "linux", "architecture": "x86_64", "kernel_filename": kernel.name,
		"initramfs_filename": initramfs.name, "kernel_sha256": sha256_file(kernel),
		"initramfs_sha256": sha256_file(initramfs), "bootable": bootable,
		"build_kind": build_kind, "secure_boot_compatible": secure_boot_compatible,
		"required_components": list(REQUIRED_IMAGE_MARKERS),
		"execution_mode": "boot_sanitize",
		"built_at": datetime.fromtimestamp(build_epoch, timezone.utc).isoformat().replace("+00:00", "Z"),
		"contains_agent_credentials": False, "contains_operator_secrets": False,
	}
	manifest = output_dir / "manifest.json"
	manifest.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
	(output_dir / "checksums.txt").write_text(
		f"{payload['kernel_sha256']}  {kernel.name}\n{payload['initramfs_sha256']}  {initramfs.name}\n",
		encoding="utf-8",
	)
	return manifest


def build_host_boot_image(output_dir: str | Path, *, kernel_version: str | None = None) -> Path:
	"""Build using Ubuntu/Debian initramfs-tools and the installed VYPER hook."""
	if os.name != "posix" or not shutil.which("mkinitramfs"):
		raise RuntimeError("A Linux host with initramfs-tools is required to build a bootable image.")
	output = Path(output_dir)
	output.mkdir(parents=True, exist_ok=True)
	version = kernel_version
	if not version:
		result = _run(["uname", "-r"], timeout=10)
		if result.returncode != 0:
			raise RuntimeError("Unable to determine the running kernel version.")
		version = result.stdout.strip()
	source_kernel = Path(f"/boot/vmlinuz-{version}")
	if not source_kernel.is_file():
		raise RuntimeError(f"Kernel image is unavailable: {source_kernel}")
	kernel = output / "vmlinuz"
	initramfs = output / "initramfs.img"
	shutil.copy2(source_kernel, kernel)
	result = _run(["mkinitramfs", "-o", str(initramfs), version], timeout=600)
	if result.returncode != 0:
		raise RuntimeError("mkinitramfs failed while building the VYPER boot environment.")
	listing = _run(["lsinitramfs", str(initramfs)], timeout=120)
	if listing.returncode != 0:
		raise RuntimeError("Unable to inspect the generated initramfs.")
	missing = [marker for marker in REQUIRED_IMAGE_MARKERS if marker not in listing.stdout]
	if missing:
		raise RuntimeError(f"Generated initramfs is missing required components: {', '.join(missing)}")
	return write_manifest(output, kernel=kernel, initramfs=initramfs, bootable=True,
		secure_boot_compatible=_secure_boot_compatible(kernel), build_kind="ubuntu-debian-initramfs-tools")


def build_fixture_boot_image(output_dir: str | Path) -> Path:
	"""Non-bootable deterministic artifact for non-Linux CI and manifest tests."""
	output = Path(output_dir)
	output.mkdir(parents=True, exist_ok=True)
	kernel = output / "vmlinuz"
	initramfs = output / "initramfs.img"
	kernel.write_bytes(b"VYPER-TEST-KERNEL\n")
	initramfs.write_bytes(b"VYPER-TEST-INITRAMFS\n" + "\n".join(REQUIRED_IMAGE_MARKERS).encode("utf-8"))
	return write_manifest(output, kernel=kernel, initramfs=initramfs, bootable=False,
		secure_boot_compatible=False, build_kind="non-bootable-test-fixture")
