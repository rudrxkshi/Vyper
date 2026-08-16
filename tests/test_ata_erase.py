from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent.command_runner import CommandResult
from agent.pathways.ata_erase import ATAErasePathway
from agent.profiler import DeviceProfile
from agent.common import SanitizationStatus


class RecordingExecutor:
    def __init__(self, responses=None, *, raise_on_call=None):
        self.calls = []
        self.responses = list(responses or [])
        self.raise_on_call = raise_on_call

    @staticmethod
    def _redact_command(command):
        redacted = list(command)
        if len(redacted) >= 6 and redacted[0] == "hdparm" and redacted[1] == "--user-master" and redacted[2] == "u":
            if redacted[3] in {"--security-set-pass", "--security-erase"}:
                redacted[4] = "<redacted>"
        elif len(redacted) >= 3 and redacted[0] == "hdparm" and redacted[1] in {"--security-set-pass", "--security-erase"}:
            redacted[2] = "<redacted>"
        return redacted

    def run(self, command, timeout=None, cwd=None):
        safe_command = self._redact_command(command)
        self.calls.append({"command": safe_command, "timeout": timeout, "cwd": cwd})
        if self.raise_on_call is not None and safe_command == list(self.raise_on_call):
            raise FileNotFoundError("hdparm missing")
        if self.responses:
            response = self.responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response
        return CommandResult(
            command=safe_command,
            success=True,
            exit_code=0,
            stdout="Security: enabled\nSecurity: not frozen\nEnhanced Secure Erase supported",
            stderr="",
            dry_run=False,
            metadata={"timeout": timeout, "cwd": cwd},
        )


def _profile(device_type: str, *, device_path: str = "/dev/sda", frozen: bool = False, security_supported: bool = True) -> DeviceProfile:
    return DeviceProfile(
        device_path=device_path,
        device_type=device_type,
        rotational=True if device_type == "HDD" else False,
        capabilities={
            "security": {
                "supported": security_supported,
                "enabled": True,
                "frozen": frozen,
                "secure_erase_supported": True,
            }
        },
    )


def test_unsupported_ata_device():
    pathway = ATAErasePathway(dry_run=True)
    profile = DeviceProfile(device_path="/dev/nvme0n1", device_type="NVMe", capabilities={})

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED
    assert "ATA" in result.message or "ATA/SATA" in result.message


def test_ata_capability_missing():
    pathway = ATAErasePathway(dry_run=True)
    profile = DeviceProfile(
        device_path="/dev/sda",
        device_type="HDD",
        rotational=True,
        capabilities={"security": {"supported": False, "enabled": False, "frozen": False, "secure_erase_supported": False}},
    )

    result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED
    assert "security" in result.message.lower()


def test_frozen_device():
    pathway = ATAErasePathway(dry_run=True)
    profile = _profile("HDD", frozen=True)

    result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED
    assert "frozen" in result.message.lower()


def test_dry_run():
    executor = RecordingExecutor()
    pathway = ATAErasePathway(dry_run=True, command_executor=executor)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True, password="SuperSecret123")

    assert result.status == SanitizationStatus.RUNNING
    assert result.dry_run is True
    assert result.metadata["planned_commands"]
    assert "SuperSecret123" not in str(result.metadata)
    assert executor.calls == []


def test_authorization_missing():
    pathway = ATAErasePathway(dry_run=True)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=False)

    assert result.status == SanitizationStatus.FAILED
    assert "authorization" in result.message.lower()


def test_successful_command_sequence():
    executor = RecordingExecutor(
        [
            CommandResult(command=["hdparm", "--user-master", "u", "--security-set-pass", "********", "/dev/sda"], success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={}),
            CommandResult(command=["hdparm", "--user-master", "u", "--security-erase-prepare", "/dev/sda"], success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={}),
            CommandResult(command=["hdparm", "--user-master", "u", "--security-erase", "********", "/dev/sda"], success=True, exit_code=0, stdout="security erase: successful", stderr="", dry_run=False, metadata={}),
            CommandResult(command=["hdparm", "-I", "/dev/sda"], success=True, exit_code=0, stdout="Security: enabled\nSecurity: not frozen", stderr="", dry_run=False, metadata={}),
        ]
    )
    pathway = ATAErasePathway(dry_run=False, command_executor=executor, timeout=30)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True, password="SuperSecret123")

    assert result.status == SanitizationStatus.RUNNING
    assert len(executor.calls) == 4
    assert executor.calls[0]["command"] == ["hdparm", "--user-master", "u", "--security-set-pass", "<redacted>", "/dev/sda"]
    assert executor.calls[1]["command"] == ["hdparm", "--user-master", "u", "--security-erase-prepare", "/dev/sda"]
    assert executor.calls[2]["command"] == ["hdparm", "--user-master", "u", "--security-erase", "<redacted>", "/dev/sda"]
    assert executor.calls[3]["command"] == ["hdparm", "-I", "/dev/sda"]
    assert "SuperSecret123" not in str(result.metadata)
    assert result.metadata["device_type"] == "HDD"


def test_security_set_pass_failure():
    executor = RecordingExecutor([
        CommandResult(command=["hdparm", "--user-master", "u", "--security-set-pass", "********", "/dev/sda"], success=False, exit_code=1, stdout="", stderr="security set-pass failed", dry_run=False, metadata={})
    ])
    pathway = ATAErasePathway(dry_run=False, command_executor=executor)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True, password="SuperSecret123")

    assert result.status == SanitizationStatus.FAILED
    assert "set-pass" in result.message.lower()


def test_erase_prepare_failure():
    executor = RecordingExecutor([
        CommandResult(command=["hdparm", "--user-master", "u", "--security-set-pass", "********", "/dev/sda"], success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["hdparm", "--user-master", "u", "--security-erase-prepare", "/dev/sda"], success=False, exit_code=1, stdout="", stderr="prepare failed", dry_run=False, metadata={}),
    ])
    pathway = ATAErasePathway(dry_run=False, command_executor=executor)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True, password="SuperSecret123")

    assert result.status == SanitizationStatus.FAILED
    assert "prepare" in result.message.lower()
    assert len(executor.calls) == 2
    assert executor.calls[1]["command"] == ["hdparm", "--user-master", "u", "--security-erase-prepare", "/dev/sda"]


def test_erase_failure():
    executor = RecordingExecutor([
        CommandResult(command=["hdparm", "--user-master", "u", "--security-set-pass", "********", "/dev/sda"], success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["hdparm", "--user-master", "u", "--security-erase-prepare", "/dev/sda"], success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["hdparm", "--user-master", "u", "--security-erase", "********", "/dev/sda"], success=False, exit_code=5, stdout="", stderr="erase failed", dry_run=False, metadata={}),
    ])
    pathway = ATAErasePathway(dry_run=False, command_executor=executor)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True, password="SuperSecret123")

    assert result.status == SanitizationStatus.FAILED
    assert "erase" in result.message.lower()
    assert len(executor.calls) == 3
    assert executor.calls[2]["command"] == ["hdparm", "--user-master", "u", "--security-erase", "<redacted>", "/dev/sda"]


def test_timeout():
    executor = RecordingExecutor([
        TimeoutError("timed out"),
    ])
    pathway = ATAErasePathway(dry_run=False, command_executor=executor)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True, password="SuperSecret123")

    assert result.status == SanitizationStatus.FAILED
    assert "timeout" in result.message.lower()


def test_command_unavailable():
    path = ATAErasePathway(dry_run=False, command_executor=RecordingExecutor())
    path.command_executor.raise_on_call = ["hdparm", "--user-master", "u", "--security-set-pass", "<redacted>", "/dev/sda"]
    profile = _profile("HDD")

    result = path.execute("/dev/sda", profile=profile, authorized=True, password="SuperSecret123")

    assert result.status == SanitizationStatus.FAILED
    assert "not found" in result.message.lower() or "unavailable" in result.message.lower()


def test_password_never_appears_in_logs_result_or_metadata():
    executor = RecordingExecutor([
        CommandResult(command=["hdparm", "--user-master", "u", "--security-set-pass", "********", "/dev/sda"], success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["hdparm", "--user-master", "u", "--security-erase-prepare", "/dev/sda"], success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["hdparm", "--user-master", "u", "--security-erase", "********", "/dev/sda"], success=True, exit_code=0, stdout="erase ok", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["hdparm", "-I", "/dev/sda"], success=True, exit_code=0, stdout="Security: enabled\nSecurity: not frozen", stderr="", dry_run=False, metadata={}),
    ])
    pathway = ATAErasePathway(dry_run=False, command_executor=executor)
    profile = _profile("HDD")
    password = "SuperSecret123"

    result = pathway.execute("/dev/sda", profile=profile, authorized=True, password=password)

    assert password not in str(result)
    assert password not in str(result.metadata)
    assert password not in str(executor.calls)


def test_nvme_rejected():
    executor = RecordingExecutor()
    pathway = ATAErasePathway(dry_run=True, command_executor=executor)
    profile = DeviceProfile(device_path="/dev/nvme0n1", device_type="NVMe", capabilities={"sanicap": {"crypto_erase": True}})

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED
    assert "NVMe" in result.message or "ATA" in result.message


def test_sata_ssd_accepted_when_capability_exists():
    executor = RecordingExecutor()
    pathway = ATAErasePathway(dry_run=True, command_executor=executor)
    profile = _profile("SATA SSD", device_path="/dev/sdb")

    result = pathway.execute("/dev/sdb", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert result.dry_run is True


def test_hdd_accepted_when_capability_exists():
    executor = RecordingExecutor()
    pathway = ATAErasePathway(dry_run=True, command_executor=executor)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert result.dry_run is True


def test_post_operation_status_collection():
    executor = RecordingExecutor([
        CommandResult(command=["hdparm", "--user-master", "u", "--security-set-pass", "********", "/dev/sda"], success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["hdparm", "--user-master", "u", "--security-erase-prepare", "/dev/sda"], success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["hdparm", "--user-master", "u", "--security-erase", "********", "/dev/sda"], success=True, exit_code=0, stdout="security erase: successful", stderr="", dry_run=False, metadata={}),
        CommandResult(command=["hdparm", "-I", "/dev/sda"], success=True, exit_code=0, stdout="Security: enabled\nSecurity: not frozen\nSecurity level high", stderr="", dry_run=False, metadata={}),
    ])
    pathway = ATAErasePathway(dry_run=False, command_executor=executor)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True, password="SuperSecret123")

    assert result.status == SanitizationStatus.RUNNING
    assert result.metadata["security_supported"] is True
    assert result.metadata["security_frozen_before"] is False
    assert result.metadata["erase_command_completed"] is True


def test_no_real_destructive_commands_executed_by_tests():
    executor = RecordingExecutor()
    pathway = ATAErasePathway(dry_run=True, command_executor=executor)
    profile = _profile("HDD")

    result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert executor.calls == []
