from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from agent.discovery import DeviceDiscovery

from .boot_handoff import BootImage, GrubOneShotHandoff, latest_boot_job
from .boot_sanitize import BootJobError, BootJobStore, device_identifiers, identity_confidence
from .initramfs import personalize_initramfs


class SystemDiskService:
	def __init__(self, *, discovery: DeviceDiscovery | Any, store: BootJobStore, handoff: GrubOneShotHandoff,
		boot_image_manifest: str | Path, boot_directory: str | Path = "/boot/vyper") -> None:
		self.discovery = discovery
		self.store = store
		self.handoff = handoff
		self.boot_image_manifest = Path(boot_image_manifest)
		self.boot_directory = Path(boot_directory)

	def detect_system_disk(self) -> dict[str, Any]:
		matches = []
		for item in self.discovery.discover():
			device = item.to_dict() if hasattr(item, "to_dict") else dict(item)
			if device.get("is_system_device") is True:
				matches.append(device)
		if len(matches) != 1:
			raise BootJobError("Exactly one active system disk must be identified before preparation.")
		identifiers = device_identifiers(matches[0])
		if identity_confidence(identifiers) == "LOW":
			raise BootJobError("The active system disk lacks a sufficiently stable hardware identity.")
		return matches[0]

	def prepare(self, *, dry_run: bool, requested_method: str = "POLICY", central_job_id: str | None = None,
		agent_id: str | None = None, central_api_url: str | None = None, agent_credential_path: str | Path | None = None,
		expires_in_seconds: int = 3600, apply_handoff: bool = True) -> dict[str, Any]:
		image = BootImage.load(self.boot_image_manifest)
		manifest_payload = json.loads(self.boot_image_manifest.read_text(encoding="utf-8"))
		if not manifest_payload.get("bootable") and apply_handoff:
			raise BootJobError("The selected boot image is a non-bootable test fixture.")
		device = self.detect_system_disk()
		document = self.store.create(device=device, boot_image_path=image.initramfs_path,
			central_job_id=central_job_id, agent_id=agent_id, central_api_url=central_api_url, requested_method=requested_method,
			dry_run=dry_run, expires_in_seconds=expires_in_seconds)
		boot_job_id = document["payload"]["boot_job_id"]
		job_boot_dir = self.boot_directory / "jobs" / boot_job_id
		job_boot_dir.mkdir(parents=True, exist_ok=False)
		kernel = job_boot_dir / "vmlinuz"
		initramfs = job_boot_dir / "initramfs.img"
		shutil.copy2(image.kernel_path, kernel)
		handoff = self.handoff.prepare(boot_job_id=boot_job_id, image=image,
			kernel_boot_path=f"/vyper/jobs/{boot_job_id}/vmlinuz",
			initramfs_boot_path=f"/vyper/jobs/{boot_job_id}/initramfs.img", apply=apply_handoff)
		state = self.store.transition(boot_job_id, "AWAITING_REBOOT", handoff=handoff,
			prepared_kernel=str(kernel), prepared_initramfs=str(initramfs))
		# Embed the post-handoff state so event sequence numbers continue monotonically
		# when the independent environment starts.
		personalize_initramfs(image.initramfs_path, initramfs,
			manifest_path=self.store.root / boot_job_id / "manifest.json", key_path=self.store.key_path,
			agent_credential_path=agent_credential_path if central_job_id else None)
		return {"boot_job": document["payload"], "state": state, "device": device, "handoff": handoff}

	def status(self, boot_job_id: str | None = None) -> dict[str, Any]:
		if boot_job_id:
			return {"boot_job_id": boot_job_id, **self.store.state(boot_job_id)}
		latest = latest_boot_job(self.store)
		if latest is None:
			return {"status": "NONE", "boot_job_id": None}
		return {"boot_job_id": latest[0], **latest[1]}

	def cancel(self, boot_job_id: str | None = None, *, apply_handoff: bool = True) -> dict[str, Any]:
		if not boot_job_id:
			latest = latest_boot_job(self.store)
			if latest is None:
				raise BootJobError("No prepared boot job exists.")
			boot_job_id = latest[0]
		self.handoff.cancel(apply=apply_handoff)
		return {"boot_job_id": boot_job_id, **self.store.cancel(boot_job_id)}
