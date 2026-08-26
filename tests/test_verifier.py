from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from agent.common import SanitizationStatus
from agent.profiler import DeviceProfile
from agent.verifier import VerificationResult, Verifier


class RecordingExecutor:
    def __init__(self, responses=None):
        self.responses = list(responses or [])
        self.calls = []

    def run(self, command, timeout=None, cwd=None):
        self.calls.append({"command": list(command), "timeout": timeout, "cwd": cwd})
        if not self.responses:
            return SimpleNamespace(success=True, exit_code=0, stdout="", stderr="", dry_run=False, metadata={})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _hdd_profile(size_bytes=64 * 1024, **kwargs):
    defaults = {
        "device_path": "/dev/sda",
        "device_type": "HDD",
        "size_bytes": size_bytes,
    }
    defaults.update(kwargs)
    return DeviceProfile(**defaults)


def _ata_profile(**kwargs):
    defaults = {
        "device_path": "/dev/sda",
        "device_type": "HDD",
        "capabilities": {
            "security": {
                "supported": True,
                "frozen": False,
                "secure_erase_supported": True,
                "raw_output": "Security: disabled",
            }
        },
    }
    defaults.update(kwargs)
    return DeviceProfile(**defaults)


def _nvme_profile(**kwargs):
    defaults = {
        "device_path": "/dev/nvme0n1",
        "device_type": "NVMe",
        "capabilities": {
            "sanicap": {"crypto_erase": True, "block_erase": True, "overwrite": True},
            "crypto_erase_applicable": True,
        },
    }
    defaults.update(kwargs)
    return DeviceProfile(**defaults)


def _sanitize_log_json(status: int, description: str = "", *, global_data_erased: bool = False) -> str:
    sstat_value = status | (0x100 if global_data_erased else 0)
    return json.dumps({"nvme0n1": {"sstat": {"status": f"({sstat_value}) {description}"}}})


def test_hdd_overwrite_sampled_zeros_are_verified():
    class ZeroFile:
        def __init__(self):
            self.mode = "rb"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def seek(self, offset, whence=0):
            return 0

        def read(self, size=-1):
            return b"\x00" * size

    verifier = Verifier()
    profile = _hdd_profile()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("builtins.open", lambda *args, **kwargs: ZeroFile())
        result = verifier.verify(device="/dev/sda", pathway="HDD_OVERWRITE", profile=profile)

    assert result.status == SanitizationStatus.VERIFIED
    assert result.verified is True
    assert result.evidence["source"] == "hdd_zero_sampling"
    assert result.samples_passed >= 1


def test_hdd_overwrite_non_zero_sample_fails():
    class NonZeroFile:
        def __init__(self):
            self.mode = "rb"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def seek(self, offset, whence=0):
            return 0

        def read(self, size=-1):
            return b"\x01" * size

    verifier = Verifier(sample_count=4, sample_size=512)
    profile = _hdd_profile(size_bytes=4096)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("builtins.open", lambda *args, **kwargs: NonZeroFile())
        result = verifier.verify(device="/dev/sda", pathway="HDD_OVERWRITE", profile=profile)

    assert result.status == SanitizationStatus.FAILED
    assert result.verified is False
    assert result.samples_failed >= 1


def test_hdd_overwrite_read_error_fails():
    verifier = Verifier()
    profile = _hdd_profile()

    def boom(*args, **kwargs):
        raise OSError("read failed")

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("builtins.open", boom)
        result = verifier.verify(device="/dev/sda", pathway="HDD_OVERWRITE", profile=profile)

    assert result.status == SanitizationStatus.FAILED
    assert "read" in " ".join(result.errors).lower()


def test_hdd_overwrite_insufficient_data_is_inconclusive():
    verifier = Verifier(sample_count=16, sample_size=4096)
    profile = _hdd_profile(size_bytes=1024)

    result = verifier.verify(device="/dev/sda", pathway="HDD_OVERWRITE", profile=profile)

    assert result.status == SanitizationStatus.INCONCLUSIVE
    assert result.verified is False
    assert "insufficient" in " ".join(result.warnings).lower()


def test_ata_verification_expected_state_is_verified():
    calls = []

    class Executor:
        def run(self, command, timeout=None, cwd=None):
            calls.append(command)
            return SimpleNamespace(success=True, exit_code=0, stdout="Security: disabled\nnot frozen\n", stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _ata_profile()

    result = verifier.verify(device="/dev/sda", pathway="ATA_ERASE", profile=profile)

    assert result.status == SanitizationStatus.VERIFIED
    assert result.verified is True
    assert calls


def test_ata_verification_unexpected_state_fails():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=True, exit_code=0, stdout="Security: enabled\n", stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _ata_profile()

    result = verifier.verify(device="/dev/sda", pathway="ATA_ERASE", profile=profile)

    assert result.status == SanitizationStatus.FAILED
    assert result.verified is False


def test_ata_verification_command_failure_fails():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=False, exit_code=1, stdout="", stderr="hdparm failed", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _ata_profile()

    result = verifier.verify(device="/dev/sda", pathway="ATA_ERASE", profile=profile)

    assert result.status == SanitizationStatus.FAILED


def test_ata_verification_malformed_output_is_inconclusive():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=True, exit_code=0, stdout="??garbage??", stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _ata_profile()

    result = verifier.verify(device="/dev/sda", pathway="ATA_ERASE", profile=profile)

    assert result.status == SanitizationStatus.INCONCLUSIVE


def test_nvme_sanitize_completed_is_verified():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=True, exit_code=0, stdout=_sanitize_log_json(1, "Completed Successfully", global_data_erased=True), stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _nvme_profile()

    result = verifier.verify(device="/dev/nvme0n1", pathway="CRYPTO_ERASE", profile=profile)

    assert result.status == SanitizationStatus.VERIFIED
    assert result.verified is True
    assert result.evidence["status"] == "COMPLETED"


def test_nvme_sanitize_log_uses_bound_controller_target():
    from agent.common import SanitizationResult

    calls = []
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            calls.append(list(command))
            return SimpleNamespace(success=True, exit_code=0, stdout=_sanitize_log_json(1, "Completed Successfully"), stderr="", dry_run=False, metadata={})

    execution = SanitizationResult(status=SanitizationStatus.RUNNING, target_device="/dev/nvme0n1", dry_run=False,
        metadata={"requested_namespace": "/dev/nvme0n1", "resolved_controller": "/dev/nvme0",
            "sanitize_target": "/dev/nvme0", "sanitize_scope": "controller"})
    result = Verifier(command_executor=Executor()).verify(device="/dev/nvme0n1", pathway="CRYPTO_ERASE",
        profile=_nvme_profile(), sanitization_result=execution)
    assert result.status == SanitizationStatus.VERIFIED
    assert calls == [["nvme", "sanitize-log", "/dev/nvme0", "--output-format=json"]]
    assert result.evidence["requested_namespace"] == "/dev/nvme0n1"
    assert result.evidence["verification_target"] == "/dev/nvme0"


def test_nvme_sanitize_in_progress_is_inconclusive():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=True, exit_code=0, stdout=_sanitize_log_json(2, "In Progress"), stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _nvme_profile()

    result = verifier.verify(device="/dev/nvme0n1", pathway="CRYPTO_ERASE", profile=profile)

    assert result.status == SanitizationStatus.INCONCLUSIVE
    assert result.verified is False


def test_nvme_sanitize_failed_is_failed():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=True, exit_code=0, stdout=_sanitize_log_json(3, "Failed"), stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _nvme_profile()

    result = verifier.verify(device="/dev/nvme0n1", pathway="CRYPTO_ERASE", profile=profile)

    assert result.status == SanitizationStatus.FAILED


def test_nvme_sanitize_aborted_is_failed():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=True, exit_code=0, stdout=_sanitize_log_json(3, "Abort requested"), stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _nvme_profile()

    result = verifier.verify(device="/dev/nvme0n1", pathway="CRYPTO_ERASE", profile=profile)

    assert result.status == SanitizationStatus.FAILED


def test_nvme_sanitize_malformed_log_is_inconclusive():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=True, exit_code=0, stdout="??garbage??", stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _nvme_profile()

    result = verifier.verify(device="/dev/nvme0n1", pathway="CRYPTO_ERASE", profile=profile)

    assert result.status == SanitizationStatus.INCONCLUSIVE


def test_nvme_sanitize_timeout_is_inconclusive():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=True, exit_code=0, stdout="status: timeout", stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _nvme_profile()

    result = verifier.verify(device="/dev/nvme0n1", pathway="CRYPTO_ERASE", profile=profile)

    assert result.status == SanitizationStatus.INCONCLUSIVE


def test_verifier_never_writes():
    class ZeroFile:
        def __init__(self):
            self.mode = "rb"

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def seek(self, offset, whence=0):
            return 0

        def read(self, size=-1):
            return b"\x00" * size

    verifier = Verifier()
    profile = _hdd_profile()

    with pytest.MonkeyPatch.context() as mp:
        def open_guard(name, mode=None, *args, **kwargs):
            assert mode in {"rb", "r", "rb"}
            return ZeroFile()

        mp.setattr("builtins.open", open_guard)
        result = verifier.verify(device="/dev/sda", pathway="HDD_OVERWRITE", profile=profile)

    assert result.status == SanitizationStatus.VERIFIED


def test_verifier_uses_command_executor_for_read_only_commands():
    class Executor:
        def run(self, command, timeout=None, cwd=None):
            return SimpleNamespace(success=True, exit_code=0, stdout="Security: disabled\nnot frozen\n", stderr="", dry_run=False, metadata={})

    verifier = Verifier(command_executor=Executor())
    profile = _ata_profile()

    result = verifier.verify(device="/dev/sda", pathway="ATA_ERASE", profile=profile)

    assert result.status == SanitizationStatus.VERIFIED
    assert result.verified is True


def test_supported_route_is_routed_correctly():
    executor = RecordingExecutor([
        SimpleNamespace(success=True, exit_code=0, stdout=_sanitize_log_json(1, "Completed Successfully", global_data_erased=True), stderr="", dry_run=False, metadata={}),
    ])
    verifier = Verifier(command_executor=executor)
    profile = _nvme_profile()

    result = verifier.verify(device="/dev/nvme0n1", pathway="BLOCK_ERASE", profile=profile)

    assert result.status == SanitizationStatus.VERIFIED
    assert result.pathway == "BLOCK_ERASE"


def test_unknown_pathway_is_unsupported():
    verifier = Verifier()
    profile = _nvme_profile()

    result = verifier.verify(device="/dev/nvme0n1", pathway="UNKNOWN_PATHWAY", profile=profile)

    assert result.status == SanitizationStatus.UNSUPPORTED
    assert result.verified is False
