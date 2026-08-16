from __future__ import annotations

from pathlib import Path

import pytest

from agent.command_runner import CommandResult
from agent.profiler import DeviceProfiler


class DummyExecutor:
    def __init__(self, responses):
        self.responses = {tuple(command): payload for command, payload in responses.items()}
        self.calls = []

    def run(self, command, timeout=None, cwd=None):
        self.calls.append({"command": command, "timeout": timeout, "cwd": cwd})
        key = tuple(command)
        if key in self.responses:
            payload = self.responses[key]
            if isinstance(payload, Exception):
                raise payload
            return CommandResult(
                command=command,
                success=payload.get("success", True),
                exit_code=payload.get("exit_code", 0),
                stdout=payload.get("stdout", ""),
                stderr=payload.get("stderr", ""),
                dry_run=False,
                metadata={"mode": "mock"},
            )
        raise AssertionError(f"Unexpected command: {command!r}")


@pytest.fixture
def tmp_sysfs(tmp_path):
    sysfs = tmp_path / "sys"
    block = sysfs / "class" / "block"
    block.mkdir(parents=True)
    return sysfs


def test_hdd_detection(tmp_sysfs):
    dev = tmp_sysfs / "class" / "block" / "sda"
    dev.mkdir(parents=True)
    (dev / "queue").mkdir()
    (dev / "queue" / "rotational").write_text("1\n", encoding="utf-8")
    (dev / "device").mkdir()
    (dev / "device" / "model").write_text("ST1000DM010\n", encoding="utf-8")
    (dev / "device" / "serial").write_text("Z1A2B3C4\n", encoding="utf-8")
    (dev / "size").write_text("2097152\n", encoding="utf-8")
    executor = DummyExecutor({
        ("hdparm", "-I", "/dev/sda"): FileNotFoundError(),
    })
    profiler = DeviceProfiler(command_executor=executor, sysfs_root=str(tmp_sysfs), mountinfo_path=str(tmp_sysfs / "mountinfo"))

    profile = profiler.profile("/dev/sda")

    assert profile.device_type == "HDD"
    assert profile.model == "ST1000DM010"
    assert profile.serial_number == "Z1A2B3C4"
    assert profile.size_bytes == 2097152 * 512
    assert profile.rotational is True


def test_sata_ssd_detection(tmp_sysfs):
    dev = tmp_sysfs / "class" / "block" / "sdb"
    dev.mkdir(parents=True)
    (dev / "queue").mkdir()
    (dev / "queue" / "rotational").write_text("0\n", encoding="utf-8")
    (dev / "device").mkdir()
    (dev / "device" / "model").write_text("Samsung SSD 860\n", encoding="utf-8")
    (dev / "device" / "serial").write_text("ABC123\n", encoding="utf-8")
    (dev / "size").write_text("4194304\n", encoding="utf-8")
    executor = DummyExecutor({
        ("hdparm", "-I", "/dev/sdb"): {
            "success": True,
            "stdout": "\nSecurity: supported\nSecurity: enabled\nSecurity: not frozen\n",
            "exit_code": 0,
        }
    })
    profiler = DeviceProfiler(command_executor=executor, sysfs_root=str(tmp_sysfs), mountinfo_path=str(tmp_sysfs / "mountinfo"))

    profile = profiler.profile("/dev/sdb")

    assert profile.device_type == "SATA SSD"
    assert profile.capabilities["security"]["supported"] is True
    assert profile.capabilities["security"]["enabled"] is True
    assert profile.capabilities["security"]["frozen"] is False


def test_nvme_detection(tmp_sysfs):
    dev = tmp_sysfs / "class" / "block" / "nvme0n1"
    dev.mkdir(parents=True)
    (dev / "device").mkdir()
    (dev / "device" / "model").write_text("NVMe SSD\n", encoding="utf-8")
    (dev / "device" / "serial").write_text("NVME123\n", encoding="utf-8")
    (dev / "size").write_text("8388608\n", encoding="utf-8")
    executor = DummyExecutor({
        ("nvme", "id-ctrl", "-H", "/dev/nvme0n1"): {
            "success": True,
            "stdout": "\nNVME Identify Controller:\n  SANICAP: 0x7\n",
            "exit_code": 0,
        }
    })
    profiler = DeviceProfiler(command_executor=executor, sysfs_root=str(tmp_sysfs), mountinfo_path=str(tmp_sysfs / "mountinfo"))

    profile = profiler.profile("/dev/nvme0n1")

    assert profile.device_type == "NVMe"
    assert profile.capabilities["sanicap"]["crypto_erase"] is True
    assert profile.capabilities["sanicap"]["block_erase"] is True
    assert profile.capabilities["sanicap"]["overwrite"] is True


def test_missing_hdparm(tmp_sysfs):
    dev = tmp_sysfs / "class" / "block" / "sdc"
    dev.mkdir(parents=True)
    (dev / "queue").mkdir()
    (dev / "queue" / "rotational").write_text("0\n", encoding="utf-8")
    executor = DummyExecutor({
        ("hdparm", "-I", "/dev/sdc"): FileNotFoundError()
    })
    profiler = DeviceProfiler(command_executor=executor, sysfs_root=str(tmp_sysfs), mountinfo_path=str(tmp_sysfs / "mountinfo"))

    profile = profiler.profile("/dev/sdc")

    assert profile.device_type == "SATA SSD"
    assert profile.capabilities["hdparm_available"] is False
    assert any("hdparm" in warning.lower() for warning in profile.warnings)


def test_missing_nvme_cli(tmp_sysfs):
    dev = tmp_sysfs / "class" / "block" / "nvme1n1"
    dev.mkdir(parents=True)
    (dev / "size").write_text("1024\n", encoding="utf-8")
    executor = DummyExecutor({
        ("nvme", "id-ctrl", "-H", "/dev/nvme1n1"): FileNotFoundError()
    })
    profiler = DeviceProfiler(command_executor=executor, sysfs_root=str(tmp_sysfs), mountinfo_path=str(tmp_sysfs / "mountinfo"))

    profile = profiler.profile("/dev/nvme1n1")

    assert profile.device_type == "NVMe"
    assert profile.capabilities["nvme_cli_available"] is False
    assert any("nvme-cli" in warning.lower() for warning in profile.warnings)


def test_ata_security_capability_parsing(tmp_sysfs):
    output = """
    ATA device is ready.
    Security: enabled
    Security: frozen
    Enhanced Secure Erase supported
    """
    profiler = DeviceProfiler(command_executor=DummyExecutor({}), sysfs_root=str(tmp_sysfs), mountinfo_path=str(tmp_sysfs / "mountinfo"))
    parsed = profiler._parse_ata_security(profile=type("MockProfile", (), {"warnings": []})(), output=output)

    assert parsed["supported"] is True
    assert parsed["enabled"] is True
    assert parsed["frozen"] is True
    assert parsed["secure_erase_supported"] is True


def test_ata_frozen_state(tmp_sysfs):
    output = """
    Security: disabled
    Security: not frozen
    """
    profiler = DeviceProfiler(command_executor=DummyExecutor({}), sysfs_root=str(tmp_sysfs), mountinfo_path=str(tmp_sysfs / "mountinfo"))
    parsed = profiler._parse_ata_security(profile=type("MockProfile", (), {"warnings": []})(), output=output)

    assert parsed["enabled"] is False
    assert parsed["frozen"] is False


def test_nvme_sanicap_parsing(tmp_sysfs):
    output = "\n  SANICAP: 0x5\n"
    profiler = DeviceProfiler(command_executor=DummyExecutor({}), sysfs_root=str(tmp_sysfs), mountinfo_path=str(tmp_sysfs / "mountinfo"))
    parsed = profiler._parse_sanicap(profile=type("MockProfile", (), {"warnings": []})(), output=output)

    assert parsed["crypto_erase"] is True
    assert parsed["block_erase"] is False
    assert parsed["overwrite"] is True


def test_unknown_unsupported_device(tmp_sysfs):
    dev = tmp_sysfs / "class" / "block" / "ram0"
    dev.mkdir(parents=True)
    (dev / "size").write_text("2048\n", encoding="utf-8")
    profiler = DeviceProfiler(
        command_executor=DummyExecutor({("hdparm", "-I", "/dev/ram0"): FileNotFoundError()}),
        sysfs_root=str(tmp_sysfs),
        mountinfo_path=str(tmp_sysfs / "mountinfo"),
    )

    profile = profiler.profile("/dev/ram0")

    assert profile.device_type == "UNKNOWN"
    assert any("not recognized" in warning.lower() for warning in profile.warnings)


def test_system_disk_detection(tmp_sysfs):
    dev = tmp_sysfs / "class" / "block" / "sda"
    dev.mkdir(parents=True)
    (dev / "size").write_text("1024\n", encoding="utf-8")
    mountinfo = tmp_sysfs / "mountinfo"
    mountinfo.write_text(
        "25 23 8:0 / / rw,relatime - ext4 /dev/sda1 / rw\n",
        encoding="utf-8",
    )
    profiler = DeviceProfiler(
        command_executor=DummyExecutor({("hdparm", "-I", "/dev/sda"): FileNotFoundError()}),
        sysfs_root=str(tmp_sysfs),
        mountinfo_path=str(mountinfo),
    )

    profile = profiler.profile("/dev/sda")

    assert profile.is_system_device is True


def test_malformed_command_output(tmp_sysfs):
    dev = tmp_sysfs / "class" / "block" / "nvme0n2"
    dev.mkdir(parents=True)
    (dev / "size").write_text("128\n", encoding="utf-8")
    executor = DummyExecutor({
        ("nvme", "id-ctrl", "-H", "/dev/nvme0n2"): {
            "success": True,
            "stdout": "\nSANICAP: malformed\n",
            "exit_code": 0,
        }
    })
    profiler = DeviceProfiler(command_executor=executor, sysfs_root=str(tmp_sysfs), mountinfo_path=str(tmp_sysfs / "mountinfo"))

    profile = profiler.profile("/dev/nvme0n2")

    assert profile.device_type == "NVMe"
    assert any("malformed" in warning.lower() for warning in profile.warnings)
