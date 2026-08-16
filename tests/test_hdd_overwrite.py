from __future__ import annotations

import os
from unittest.mock import mock_open, patch

import pytest

from agent.common import SanitizationStatus
from agent.pathways.hdd_overwrite import HDDOverwritePathway
from agent.profiler import DeviceProfile


class DummyProfile(DeviceProfile):
    pass


def _mock_block_device(path: str):
    return patch("os.path.exists", side_effect=lambda p: p == path), patch("os.stat", side_effect=lambda p: type("StatResult", (), {"st_mode": 0o060000})())


def test_successful_dry_run():
    profile = DeviceProfile(
        device_path="/dev/sda",
        device_type="HDD",
        size_bytes=1024,
        rotational=True,
        is_system_device=False,
    )
    pathway = HDDOverwritePathway(dry_run=True)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1]:
        result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert result.dry_run is True
    assert result.metadata["method"] == "HDD_OVERWRITE"
    assert result.metadata["planned_method"] == "HDD_OVERWRITE"
    assert result.metadata["planned_size"] == 1024


def test_hdd_validation():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=1024, rotational=True, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=True)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1]:
        result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert result.dry_run is True


def test_ssd_rejected():
    profile = DeviceProfile(device_path="/dev/sdb", device_type="SATA SSD", size_bytes=1024, rotational=False, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=True)

    result = pathway.execute("/dev/sdb", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED
    assert "hdd devices" in result.message.lower()


def test_nvme_rejected():
    profile = DeviceProfile(device_path="/dev/nvme0n1", device_type="NVMe", size_bytes=1024, rotational=None, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=True)

    result = pathway.execute("/dev/nvme0n1", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED
    assert "hdd" in result.message.lower()


def test_unknown_device_rejected():
    profile = DeviceProfile(device_path="/dev/ram0", device_type="UNKNOWN", size_bytes=1024, rotational=None, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=True)

    result = pathway.execute("/dev/ram0", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.UNSUPPORTED


def test_missing_target_rejected():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=1024, rotational=True, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=True)

    result = pathway.execute("", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "No target device" in result.message


def test_system_associated_target_rejected():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=1024, rotational=True, is_system_device=True)
    pathway = HDDOverwritePathway(dry_run=False)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1]:
        result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "running system" in result.message.lower()


def test_unauthorized_execution_rejected():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=1024, rotational=True, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=False)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1]:
        result = pathway.execute("/dev/sda", profile=profile, authorized=False)

    assert result.status == SanitizationStatus.FAILED
    assert "authorization" in result.message.lower()


def test_successful_mocked_overwrite():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=4096, rotational=True, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=False, chunk_size=128)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1], patch("builtins.open", mock_open()) as mocked_file:
        handle = mocked_file.return_value.__enter__.return_value
        handle.write.return_value = 128
        handle.fileno.return_value = 42

        result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.RUNNING
    assert result.metadata["bytes_written"] == 4096
    assert result.metadata["total_bytes"] == 4096
    assert result.metadata["method"] == "HDD_OVERWRITE"


def test_permission_error():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=4096, rotational=True, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=False, chunk_size=128)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1], patch("builtins.open", side_effect=PermissionError("denied")):
        result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "permission" in result.message.lower()


def test_io_failure():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=4096, rotational=True, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=False, chunk_size=128)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1], patch("builtins.open", mock_open()) as mocked_file:
        handle = mocked_file.return_value.__enter__.return_value
        handle.write.side_effect = OSError("disk error")

        result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "i/o failure" in result.message.lower()


def test_short_write():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=4096, rotational=True, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=False, chunk_size=128)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1], patch("builtins.open", mock_open()) as mocked_file:
        handle = mocked_file.return_value.__enter__.return_value
        handle.write.return_value = 32

        result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "short write" in result.message.lower()


def test_interruption():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=4096, rotational=True, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=False, chunk_size=128)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1], patch("builtins.open", mock_open()) as mocked_file:
        handle = mocked_file.return_value.__enter__.return_value
        handle.write.side_effect = InterruptedError("interrupted")

        result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.status == SanitizationStatus.FAILED
    assert "interrupted" in result.message.lower()


def test_progress_reporting():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=4096, rotational=True, is_system_device=False)
    reports = []
    pathway = HDDOverwritePathway(dry_run=False, chunk_size=128, progress_callback=reports.append)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1], patch("builtins.open", mock_open()) as mocked_file:
        handle = mocked_file.return_value.__enter__.return_value
        handle.write.return_value = 128
        handle.fileno.return_value = 42

        pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert reports
    assert reports[0].bytes_written > 0
    assert reports[0].percentage >= 0.0


def test_result_metadata():
    profile = DeviceProfile(device_path="/dev/sda", device_type="HDD", size_bytes=4096, rotational=True, is_system_device=False)
    pathway = HDDOverwritePathway(dry_run=False, chunk_size=128)

    with _mock_block_device("/dev/sda")[0], _mock_block_device("/dev/sda")[1], patch("builtins.open", mock_open()) as mocked_file:
        handle = mocked_file.return_value.__enter__.return_value
        handle.write.return_value = 128
        handle.fileno.return_value = 42

        result = pathway.execute("/dev/sda", profile=profile, authorized=True)

    assert result.metadata["device_type"] == "HDD"
    assert result.metadata["duration_seconds"] >= 0.0
    assert result.metadata["throughput"] >= 0.0
