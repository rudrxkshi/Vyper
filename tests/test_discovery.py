from __future__ import annotations

import json

from agent.command_runner import CommandResult
from agent.discovery import DeviceDiscovery
from agent.profiler import DeviceProfile


class LsblkExecutor:
	def __init__(self, blockdevices):
		self.blockdevices = blockdevices
		self.calls = []

	def run(self, command, timeout=None, cwd=None):
		self.calls.append(list(command))
		return CommandResult(
			command=command,
			success=True,
			exit_code=0,
			stdout=json.dumps({"blockdevices": self.blockdevices}),
			dry_run=False,
		)


class ProfileStub:
	def __init__(self, profiles):
		self.profiles = profiles
		self.calls = []

	def profile(self, device_path):
		self.calls.append(device_path)
		result = self.profiles[device_path]
		if isinstance(result, Exception):
			raise result
		return result


def _profile(path, device_type, **overrides):
	profile = DeviceProfile(
		device_path=path,
		device_type=device_type,
		model=f"{device_type} model",
		serial_number=f"{device_type}-serial",
		size_bytes=1000,
		rotational=device_type == "HDD",
		interface="NVMe" if device_type == "NVMe" else "ATA/SATA",
		transport="PCIe" if device_type == "NVMe" else "SATA",
		capabilities={"profiled": True},
	)
	for key, value in overrides.items():
		setattr(profile, key, value)
	return profile


def _inventory():
	return [
		{
			"name": "sda",
			"path": "/dev/sda",
			"type": "disk",
			"size": 1000,
			"rota": 1,
			"children": [
				{
					"name": "sda2",
					"path": "/dev/sda2",
					"type": "part",
					"mountpoints": ["/"],
				}
			],
		},
		{"name": "sdb", "path": "/dev/sdb", "type": "disk", "size": 2000, "rota": 0},
		{"name": "nvme0n1", "path": "/dev/nvme0n1", "type": "disk", "size": 3000, "rota": 0},
		{"name": "sdc", "path": "/dev/sdc", "type": "disk", "size": 4000, "rota": 1},
		{"name": "loop0", "path": "/dev/loop0", "type": "loop"},
		{"name": "ram0", "path": "/dev/ram0", "type": "disk"},
		{"name": "sr0", "path": "/dev/sr0", "type": "rom"},
		{"name": "dm-0", "path": "/dev/dm-0", "type": "disk"},
		{"name": "sdb1", "path": "/dev/sdb1", "type": "part", "pkname": "sdb"},
	]


def _discover():
	profiles = {
		"/dev/sda": _profile(
			"/dev/sda",
			"HDD",
			is_system_device=True,
			mounted=True,
			mounted_partitions=["/"],
		),
		"/dev/sdb": _profile("/dev/sdb", "SATA SSD", serial_number=None),
		"/dev/nvme0n1": _profile("/dev/nvme0n1", "NVMe"),
		"/dev/sdc": RuntimeError("profile probe failed"),
	}
	discovery = DeviceDiscovery(
		command_executor=LsblkExecutor(_inventory()),
		profiler=ProfileStub(profiles),
	)
	return discovery.discover()


def test_multiple_disks_are_discovered_with_hdd_sata_and_nvme_profiles():
	devices = _discover()
	by_path = {device.device_path: device for device in devices}

	assert set(by_path) == {"/dev/sda", "/dev/sdb", "/dev/nvme0n1", "/dev/sdc"}
	assert by_path["/dev/sda"].device_type == "HDD"
	assert by_path["/dev/sdb"].device_type == "SATA SSD"
	assert by_path["/dev/nvme0n1"].device_type == "NVMe"
	assert by_path["/dev/sdb"].serial_number is None


def test_loop_pseudo_optical_and_partition_entries_are_excluded():
	paths = {device.device_path for device in _discover()}

	assert "/dev/loop0" not in paths
	assert "/dev/ram0" not in paths
	assert "/dev/sr0" not in paths
	assert "/dev/dm-0" not in paths
	assert "/dev/sdb1" not in paths


def test_one_profile_failure_does_not_hide_other_devices_and_is_not_safe():
	by_path = {device.device_path: device for device in _discover()}

	assert by_path["/dev/sdc"].profile_error == "Profiling failed: profile probe failed"
	assert by_path["/dev/sdc"].is_system_device is None
	assert by_path["/dev/sdc"].eligible_for_sanitization is False
	assert by_path["/dev/sda"].device_type == "HDD"


def test_system_and_mounted_disk_remains_visible_and_flagged():
	by_path = {device.device_path: device for device in _discover()}
	system_disk = by_path["/dev/sda"]

	assert system_disk.is_system_device is True
	assert system_disk.mounted is True
	assert system_disk.mounted_partitions == [{"path": "/dev/sda2", "mountpoint": "/"}]
	assert system_disk.eligible_for_sanitization is False

