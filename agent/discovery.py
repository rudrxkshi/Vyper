from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from agent.command_runner import CommandExecutor, SubprocessCommandExecutor
from agent.profiler import DeviceProfile, DeviceProfiler


class DeviceDiscoveryError(RuntimeError):
	"""Raised when the read-only system inventory cannot be enumerated."""


@dataclass(slots=True)
class DiscoveredDevice:
	device_path: str
	device_type: str = "UNKNOWN"
	model: str | None = None
	serial_number: str | None = None
	size_bytes: int | None = None
	interface: str | None = None
	transport: str | None = None
	rotational: bool | None = None
	mounted: bool = False
	mounted_partitions: list[dict[str, str | None]] = field(default_factory=list)
	is_system_device: bool | None = None
	capabilities: dict[str, Any] = field(default_factory=dict)
	warnings: list[str] = field(default_factory=list)
	profile_error: str | None = None
	eligible_for_sanitization: bool = False

	def to_dict(self) -> dict[str, Any]:
		return asdict(self)


class DeviceDiscovery:
	"""Enumerate whole block-storage candidates using read-only Linux interfaces."""

	_LSBLK_COMMAND = [
		"lsblk",
		"--json",
		"--bytes",
		"--output",
		"NAME,PATH,TYPE,PKNAME,MODEL,SERIAL,SIZE,ROTA,TRAN,MOUNTPOINT,MOUNTPOINTS",
	]
	_EXCLUDED_PREFIXES = ("loop", "ram", "zram", "dm-", "sr", "fd")

	def __init__(
		self,
		*,
		command_executor: CommandExecutor | None = None,
		profiler: DeviceProfiler | None = None,
	) -> None:
		self.command_executor = command_executor or SubprocessCommandExecutor()
		self.profiler = profiler or DeviceProfiler(command_executor=self.command_executor)

	def discover(self) -> list[DiscoveredDevice]:
		try:
			result = self.command_executor.run(self._LSBLK_COMMAND, timeout=15)
		except (FileNotFoundError, OSError) as exc:
			raise DeviceDiscoveryError(f"lsblk is unavailable: {exc}") from exc

		if not result.success or result.exit_code != 0:
			detail = (result.stderr or result.stdout or "unknown lsblk error").strip()
			raise DeviceDiscoveryError(f"lsblk discovery failed: {detail}")

		try:
			payload = json.loads(result.stdout or "{}")
		except (TypeError, json.JSONDecodeError) as exc:
			raise DeviceDiscoveryError("lsblk returned malformed JSON.") from exc

		devices = payload.get("blockdevices")
		if not isinstance(devices, list):
			raise DeviceDiscoveryError("lsblk JSON did not contain a blockdevices list.")

		discovered: list[DiscoveredDevice] = []
		for node in devices:
			if not isinstance(node, dict) or not self._is_candidate(node):
				continue
			discovered.append(self._profile_candidate(node))
		return discovered

	def _is_candidate(self, node: dict[str, Any]) -> bool:
		name = str(node.get("name") or "").strip().lower()
		path = str(node.get("path") or "").strip().lower()
		device_type = str(node.get("type") or "").strip().lower()
		if device_type != "disk":
			return False
		if not name or name.startswith(self._EXCLUDED_PREFIXES):
			return False
		if path.startswith("/dev/mapper/") or path.startswith("/dev/dm-"):
			return False
		return True

	def _profile_candidate(self, node: dict[str, Any]) -> DiscoveredDevice:
		device_path = str(node.get("path") or f"/dev/{node.get('name', '')}").strip()
		mounts = self._collect_mounts(node)
		try:
			profile = self.profiler.profile(device_path)
		except Exception as exc:
			return DiscoveredDevice(
				device_path=device_path,
				model=self._optional_text(node.get("model")),
				serial_number=self._optional_text(node.get("serial")),
				size_bytes=self._optional_int(node.get("size")),
				transport=self._optional_text(node.get("tran")),
				rotational=self._optional_bool(node.get("rota")),
				mounted=bool(mounts),
				mounted_partitions=mounts,
				is_system_device=None,
				warnings=["Device profiling failed; the device must not be treated as safe."],
				profile_error=f"Profiling failed: {exc}",
				eligible_for_sanitization=False,
			)

		return self._from_profile(profile, node=node, mounts=mounts)

	def _from_profile(
		self,
		profile: DeviceProfile,
		*,
		node: dict[str, Any],
		mounts: list[dict[str, str | None]],
	) -> DiscoveredDevice:
		profile_error = "; ".join(str(item) for item in profile.errors) or None
		mounted = bool(profile.mounted or mounts)
		is_system_device = bool(profile.is_system_device)
		device_type = str(profile.device_type or "UNKNOWN")
		return DiscoveredDevice(
			device_path=profile.device_path,
			device_type=device_type,
			model=profile.model or self._optional_text(node.get("model")),
			serial_number=profile.serial_number or self._optional_text(node.get("serial")),
			size_bytes=profile.size_bytes if profile.size_bytes is not None else self._optional_int(node.get("size")),
			interface=profile.interface,
			transport=profile.transport or self._optional_text(node.get("tran")),
			rotational=profile.rotational if profile.rotational is not None else self._optional_bool(node.get("rota")),
			mounted=mounted,
			mounted_partitions=mounts or [
				{"path": profile.device_path, "mountpoint": mountpoint}
				for mountpoint in profile.mounted_partitions
			],
			is_system_device=is_system_device,
			capabilities=dict(profile.capabilities or {}),
			warnings=list(profile.warnings or []),
			profile_error=profile_error,
			eligible_for_sanitization=(
				profile_error is None
				and device_type != "UNKNOWN"
				and not is_system_device
			),
		)

	def _collect_mounts(self, node: dict[str, Any]) -> list[dict[str, str | None]]:
		mounts: list[dict[str, str | None]] = []

		def visit(current: dict[str, Any]) -> None:
			path = self._optional_text(current.get("path"))
			values = current.get("mountpoints")
			if not isinstance(values, list):
				values = [current.get("mountpoint")]
			for value in values:
				mountpoint = self._optional_text(value)
				if mountpoint:
					entry = {"path": path, "mountpoint": mountpoint}
					if entry not in mounts:
						mounts.append(entry)
			for child in current.get("children") or []:
				if isinstance(child, dict):
					visit(child)

		visit(node)
		return mounts

	def _optional_text(self, value: Any) -> str | None:
		if value is None:
			return None
		text = str(value).strip()
		return text or None

	def _optional_int(self, value: Any) -> int | None:
		try:
			return int(value) if value is not None else None
		except (TypeError, ValueError):
			return None

	def _optional_bool(self, value: Any) -> bool | None:
		if isinstance(value, bool):
			return value
		if value in (0, "0"):
			return False
		if value in (1, "1"):
			return True
		return None
