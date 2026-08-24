from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from agent.command_runner import CommandExecutor, CommandResult, SubprocessCommandExecutor


@dataclass(slots=True)
class DeviceProfile:
    device_path: str
    device_type: str
    serial_number: str | None = None
    model: str | None = None
    size_bytes: int | None = None
    rotational: bool | None = None
    interface: str | None = None
    transport: str | None = None
    is_system_device: bool = False
    mounted: bool = False
    mounted_partitions: list[str] = field(default_factory=list)
    capabilities: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class DeviceProfiler:
    def __init__(
        self,
        *,
        dry_run: bool = True,
        command_executor: CommandExecutor | None = None,
        sysfs_root: str = "/sys",
        mountinfo_path: str = "/proc/self/mountinfo",
    ) -> None:
        self.dry_run = dry_run
        self.command_executor = command_executor or SubprocessCommandExecutor()
        self.sysfs_root = Path(sysfs_root)
        self.mountinfo_path = Path(mountinfo_path)

    def profile(self, device_path: str) -> DeviceProfile:
        profile = DeviceProfile(device_path=device_path, device_type="UNKNOWN")
        device_name = self._normalize_device_name(device_path)
        if not device_name:
            profile.errors.append("Device path is empty or malformed.")
            return profile

        sysfs_block_dir = self.sysfs_root / "class" / "block" / device_name
        profile.model = self._read_file(sysfs_block_dir / "device" / "model") or self._read_file(sysfs_block_dir / "model")
        profile.serial_number = ( self._read_file(sysfs_block_dir / "device" / "serial") or self._read_file(sysfs_block_dir / "serial") or self._serial_from_lsblk(device_path) )
        profile.size_bytes = self._read_size_bytes(sysfs_block_dir)
        profile.rotational = self._read_rotational(sysfs_block_dir)
        profile.transport = self._read_file(sysfs_block_dir / "device" / "transport") or self._read_file(sysfs_block_dir / "transport")
        profile.interface = self._infer_interface(device_name, profile.transport)

        profile.mounted, profile.mounted_partitions = self._detect_mount_state(device_name, device_path)
        profile.is_system_device = self._is_system_device(device_name, device_path)

        if "nvme" in device_name.lower():
            profile.device_type = "NVMe"
            profile.capabilities = self._profile_nvme(profile, device_path, device_name)
        else:
            if profile.rotational is True:
                profile.device_type = "HDD"
            elif profile.rotational is False:
                profile.device_type = "SATA SSD"
            elif self._looks_like_ata(device_name, profile.interface):
                profile.device_type = "SATA SSD"
            else:
                profile.device_type = "UNKNOWN"
                profile.warnings.append(f"Unable to classify device {device_path}; no reliable rotating or non-rotating signal was found.")

            profile.capabilities = self._profile_ata(profile, device_path, device_name)

        if profile.device_type == "UNKNOWN":
            profile.warnings.append(f"Device {device_path} is not recognized as HDD, SATA SSD, or NVMe.")

        profile.capabilities.update(self._persistent_identifiers(sysfs_block_dir))
        return profile

    def _persistent_identifiers(self, sysfs_block_dir: Path) -> dict[str, str]:
        identifiers: dict[str, str] = {}
        candidates = {
            "nvme_nguid": (sysfs_block_dir / "nguid", sysfs_block_dir / "device" / "nguid"),
            "nvme_eui64": (sysfs_block_dir / "eui", sysfs_block_dir / "device" / "eui"),
            "wwn": (sysfs_block_dir / "wwid", sysfs_block_dir / "device" / "wwid"),
        }
        for key, paths in candidates.items():
            value = next((item for path in paths if (item := self._read_file(path))), None)
            if value:
                identifiers[key] = value.strip().lower()
        return identifiers

    def _normalize_device_name(self, device_path: str) -> str:
        raw = str(device_path or "").strip()
        if not raw:
            return ""
        name = raw.split("/")[-1]
        if not name or name in {"", ".", ".."}:
            return ""
        return name

    def _read_file(self, path: Path) -> str | None:
        try:
            if not path.exists():
                return None
            value = path.read_text(encoding="utf-8", errors="replace").strip()
            return value or None
        except OSError:
            return None

    def _serial_from_lsblk(self, device_path: str) -> str | None:
        """Return the device serial reported by lsblk, if available."""
        try:
            result = self.command_executor.run(
                ["lsblk", "-dn", "-o", "SERIAL", device_path]
            )

            if not result.success or result.exit_code != 0:
                return None

            serial = result.stdout.strip()
            return serial or None

        except Exception:
            return None

    def _read_size_bytes(self, sysfs_block_dir: Path) -> int | None:
        size_text = self._read_file(sysfs_block_dir / "size")
        if size_text is None:
            return None
        try:
            size_blocks = int(size_text)
        except ValueError:
            return None
        return size_blocks * 512

    def _read_rotational(self, sysfs_block_dir: Path) -> bool | None:
        rotational_text = self._read_file(sysfs_block_dir / "queue" / "rotational")
        if rotational_text is None:
            rotational_text = self._read_file(sysfs_block_dir / "device" / "queue" / "rotational")
        if rotational_text is None:
            return None
        try:
            return bool(int(rotational_text))
        except ValueError:
            return None

    def _infer_interface(self, device_name: str, transport: str | None) -> str | None:
        if "nvme" in device_name.lower():
            return "NVMe"
        if transport:
            return transport.strip().upper() or None
        return "ATA/SATA" if "sd" in device_name or "hd" in device_name else None

    def _looks_like_ata(self, device_name: str, interface: str | None) -> bool:
        lowered = device_name.lower()
        if "sd" in lowered or "hd" in lowered or "sr" in lowered:
            return True
        if interface and ("ata" in interface.lower() or "sata" in interface.lower()):
            return True
        return False

    def _profile_ata(self, profile: DeviceProfile, device_path: str, device_name: str) -> dict[str, Any]:
        capabilities: dict[str, Any] = {"type": "ATA/SATA"}
        hdparm_cmd = ["hdparm", "-I", device_path]
        result: CommandResult | None = None
        try:
            result = self.command_executor.run(hdparm_cmd, timeout=10)
        except FileNotFoundError:
            capabilities["hdparm_available"] = False
            self._append_warning(profile, f"hdparm is not installed or not available for {device_path}; ATA security capabilities were not queried.")
            return capabilities

        if not result.success:
            capabilities["hdparm_available"] = False
            self._append_warning(profile, f"hdparm query for {device_path} failed: {result.stderr or result.stdout or 'unknown error'}")
            return capabilities

        text = result.stdout or ""
        capabilities["hdparm_available"] = True
        capabilities["security"] = self._parse_ata_security(profile, text)
        return capabilities

    def _parse_ata_security(self, profile: DeviceProfile, output: str) -> dict[str, Any]:
        security: dict[str, Any] = {
            "supported": False,
            "enabled": False,
            "frozen": False,
            "secure_erase_supported": False,
            "raw_output": output.strip(),
        }
        if not output:
            return security

        lowered = output.lower()
        security["supported"] = "security:" in lowered or "security support" in lowered
        if "security: enabled" in lowered or "security enabled" in lowered:
            security["enabled"] = True
        if "security: disabled" in lowered or "security disabled" in lowered:
            security["enabled"] = False
        if "security: not frozen" in lowered or "not frozen" in lowered:
            security["frozen"] = False
        elif "security: frozen" in lowered or "frozen" in lowered:
            security["frozen"] = True
        if "enhanced secure erase" in lowered or "secure erase" in lowered:
            security["secure_erase_supported"] = True

        for line in output.splitlines():
            lower_line = line.lower()
            if "security:" in lower_line:
                security["status_line"] = line.strip()
            if "security level" in lower_line:
                security["level_line"] = line.strip()
            if "not frozen" in lower_line or "frozen" in lower_line:
                security["freeze_line"] = line.strip()

        return security

    def _profile_nvme(self, profile: DeviceProfile, device_path: str, device_name: str) -> dict[str, Any]:
        capabilities: dict[str, Any] = {"type": "NVMe"}
        nvme_cmd = ["nvme", "id-ctrl", "-H", device_path]
        try:
            result = self.command_executor.run(nvme_cmd, timeout=10)
        except FileNotFoundError:
            capabilities["nvme_cli_available"] = False
            self._append_warning(profile, f"nvme-cli is not installed or not available for {device_path}; NVMe SANICAP was not queried.")
            return capabilities

        if not result.success:
            capabilities["nvme_cli_available"] = False
            self._append_warning(profile, f"nvme id-ctrl query for {device_path} failed: {result.stderr or result.stdout or 'unknown error'}")
            return capabilities

        text = result.stdout or ""
        capabilities["nvme_cli_available"] = True
        capabilities["sanicap"] = self._parse_sanicap(profile, text)
        return capabilities

    def _parse_sanicap(self, profile: DeviceProfile, output: str) -> dict[str, Any]:
        parsed = {
            "crypto_erase": False,
            "block_erase": False,
            "overwrite": False,
            "raw": None,
        }
        if not output:
            return parsed

        for line in output.splitlines():
            if "sanicap" not in line.lower():
                continue
            payload = line.split(":", 1)[-1].strip()
            try:
                value = int(payload, 16) if payload.lower().startswith("0x") else int(payload)
            except (TypeError, ValueError):
                self._append_warning(profile, "Malformed NVMe SANICAP output encountered; capability bits could not be parsed.")
                return parsed
            parsed["raw"] = payload
            parsed["crypto_erase"] = bool(value & 0x1)
            parsed["block_erase"] = bool(value & 0x2)
            parsed["overwrite"] = bool(value & 0x4)
            return parsed

        self._append_warning(profile, "NVMe SANICAP field was missing from the command output; capability claims are unknown.")
        return parsed

    def _detect_mount_state(self, device_name: str, device_path: str) -> tuple[bool, list[str]]:
        mounted_partitions: list[str] = []
        if not self.mountinfo_path.exists():
            return False, mounted_partitions

        try:
            mountinfo = self.mountinfo_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False, mounted_partitions

        candidates = {device_name, device_path}
        if device_path.startswith("/dev/"):
            candidates.add(device_path.split("/")[-1])
            candidates.add(self._base_block_name(device_path))

        for line in mountinfo.splitlines():
            if " - " not in line:
                continue
            left, right = line.split(" - ", 1)
            left_fields = left.split()
            right_fields = right.split()
            if len(left_fields) < 5 or len(right_fields) < 2:
                continue
            source = right_fields[1]
            mountpoint = left_fields[4]
            if self._is_match_for_device(source, candidates):
                mounted_partitions.append(mountpoint)

        return bool(mounted_partitions), mounted_partitions

    def _is_system_device(self, device_name: str, device_path: str) -> bool:
        if not self.mountinfo_path.exists():
            return False

        try:
            mountinfo = self.mountinfo_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False

        candidates = {device_name, device_path}
        if device_path.startswith("/dev/"):
            candidates.add(device_path.split("/")[-1])
            candidates.add(self._base_block_name(device_path))

        for line in mountinfo.splitlines():
            if " - " not in line:
                continue
            left, right = line.split(" - ", 1)
            mount_fields = left.split()
            right_fields = right.split()
            if len(mount_fields) < 5 or len(right_fields) < 2:
                continue
            mount_point = mount_fields[4]
            if mount_point != "/":
                continue
            source = right_fields[1]
            if self._is_match_for_device(source, candidates):
                return True
        return False

    def _is_match_for_device(self, source: str, candidates: set[str]) -> bool:
        source_clean = source.strip()
        fragments = {source_clean}
        if source_clean.startswith("/dev/"):
            fragments.add(source_clean.split("/")[-1])
            fragments.add(self._base_block_name(source_clean))
        for candidate in candidates:
            normalized = candidate.strip()
            if normalized in fragments:
                return True
            if normalized.endswith("p1") and normalized[:-2] in fragments:
                return True
            if self._base_block_name(normalized) in fragments:
                return True
            if normalized in source_clean or source_clean in normalized:
                return True
        return False

    def _base_block_name(self, value: str) -> str:
        ref = value.split("/")[-1]
        match = re.search(r"^(.*?)(p?\d+)$", ref)
        if match:
            return match.group(1)
        return ref

    def _append_warning(self, profile: DeviceProfile, message: str) -> None:
        profile.warnings.append(message)
