from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from agent.command_runner import CommandExecutor, SubprocessCommandExecutor

from .boot_sanitize import BootJobError, BootJobStore, sha256_file


GRUB_ENTRY_NAME = "VYPER Boot Sanitize"


@dataclass(frozen=True)
class BootImage:
	kernel_path: Path
	initramfs_path: Path
	manifest_path: Path
	version: str
	secure_boot_compatible: bool

	@classmethod
	def load(cls, manifest_path: str | Path) -> "BootImage":
		path = Path(manifest_path)
		payload = json.loads(path.read_text(encoding="utf-8"))
		kernel = path.parent / payload["kernel_filename"]
		initramfs = path.parent / payload["initramfs_filename"]
		if not kernel.is_file() or not initramfs.is_file():
			raise BootJobError("Prepared kernel or initramfs is missing.")
		if sha256_file(kernel) != payload["kernel_sha256"] or sha256_file(initramfs) != payload["initramfs_sha256"]:
			raise BootJobError("Boot image checksum validation failed.")
		return cls(kernel, initramfs, path, str(payload["version"]), bool(payload.get("secure_boot_compatible", False)))


class GrubOneShotHandoff:
	"""Ubuntu/Debian GRUB2 one-shot handoff; never changes saved/default boot."""
	def __init__(self, *, command_executor: CommandExecutor | None = None,
		grub_script_path: str | Path = "/etc/grub.d/42_vyper_boot_sanitize") -> None:
		self.command_executor = command_executor or SubprocessCommandExecutor()
		self.grub_script_path = Path(grub_script_path)

	def secure_boot_state(self) -> str:
		try:
			result = self.command_executor.run(["mokutil", "--sb-state"], timeout=10)
		except (OSError, FileNotFoundError):
			return "UNKNOWN"
		text = f"{result.stdout}\n{result.stderr}".lower()
		if result.success and "enabled" in text:
			return "ENABLED"
		if result.success and "disabled" in text:
			return "DISABLED"
		return "UNKNOWN"

	def render_entry(self, *, boot_job_id: str, kernel_boot_path: str, initramfs_boot_path: str) -> str:
		if not kernel_boot_path.startswith("/") or not initramfs_boot_path.startswith("/"):
			raise ValueError("GRUB boot paths must be absolute.")
		return "\n".join([
			"#!/bin/sh", "exec tail -n +3 $0", f"menuentry '{GRUB_ENTRY_NAME}' --id vyper-boot-sanitize {{",
			f"    linux {kernel_boot_path} vyper.mode=boot_sanitize vyper.boot_job={boot_job_id} noresume rd.shell=0",
			f"    initrd {initramfs_boot_path}", "}", "",
		])

	def prepare(self, *, boot_job_id: str, image: BootImage, kernel_boot_path: str = "/vyper/vmlinuz",
		initramfs_boot_path: str = "/vyper/initramfs.img", apply: bool = True) -> dict[str, Any]:
		secure_boot = self.secure_boot_state()
		if secure_boot == "ENABLED" and not image.secure_boot_compatible:
			raise BootJobError("Secure Boot is enabled but the VYPER boot image is not signed by a trusted key.")
		entry = self.render_entry(boot_job_id=boot_job_id, kernel_boot_path=kernel_boot_path,
			initramfs_boot_path=initramfs_boot_path)
		if apply:
			self.grub_script_path.parent.mkdir(parents=True, exist_ok=True)
			self.grub_script_path.write_text(entry, encoding="utf-8")
			os.chmod(self.grub_script_path, 0o755)
			self._required(["update-grub"])
			self._required(["swapoff", "--all"])
			self._required(["grub-reboot", GRUB_ENTRY_NAME])
		return {"mechanism": "grub2-one-shot", "entry_name": GRUB_ENTRY_NAME, "secure_boot_state": secure_boot,
			"normal_default_unchanged": True, "configuration": entry, "applied": apply}

	def cancel(self, *, apply: bool = True) -> None:
		if apply:
			self._required(["grub-editenv", "-", "unset", "next_entry"])

	def reboot(self, *, apply: bool = True) -> None:
		if apply:
			self._required(["systemctl", "reboot"])

	def _required(self, command: list[str]) -> None:
		result = self.command_executor.run(command, timeout=120)
		if not result.success or result.exit_code != 0:
			raise BootJobError(f"Boot handoff command failed: {command[0]}.")


def latest_boot_job(store: BootJobStore) -> tuple[str, dict[str, Any]] | None:
	candidates = []
	for path in store.root.iterdir():
		if path.is_dir() and (path / "state.json").is_file():
			candidates.append((path.stat().st_mtime, path.name, store.state(path.name)))
	if not candidates:
		return None
	_, boot_job_id, state = max(candidates)
	return boot_job_id, state
