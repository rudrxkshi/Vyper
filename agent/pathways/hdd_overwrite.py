from __future__ import annotations

import os
import stat
import time
from dataclasses import dataclass
from typing import Any, Callable

from agent.common import SanitizationResult, SanitizationStatus
from agent.pathways.base import SanitizationPathway
from agent.profiler import DeviceProfile


@dataclass(slots=True)
class HDDOverwriteProgress:
    bytes_written: int = 0
    total_bytes: int = 0
    percentage: float = 0.0
    elapsed_seconds: float = 0.0
    throughput: float = 0.0


class HDDOverwritePathway(SanitizationPathway):
    def __init__(
        self,
        *,
        dry_run: bool = True,
        chunk_size: int = 4 * 1024 * 1024,
        progress_callback: Callable[[HDDOverwriteProgress], None] | None = None,
        rate_reporting: bool = False,
        command_executor=None,
    ) -> None:
        super().__init__(dry_run=dry_run, command_executor=command_executor)
        self.chunk_size = max(1, int(chunk_size))
        self.progress_callback = progress_callback
        self.rate_reporting = rate_reporting

    def execute(
        self,
        target: str,
        *,
        profile: DeviceProfile | None = None,
        authorized: bool = False,
        system_associated: bool | None = None,
    ) -> SanitizationResult:
        if not target or not str(target).strip():
            return self._failed_result(target, "No target device was provided.")

        if profile is None:
            return self._failed_result(target, "A DeviceProfile is required before destructive execution.")

        if not self._target_matches_profile(target, profile):
            return self._failed_result(target, "Target identity does not match the provided profile.")

        if profile.device_type != "HDD":
            return self._unsupported_result(target, f"Pathway is only valid for HDD devices; got {profile.device_type!r}.")

        if system_associated is None:
            system_associated = bool(profile.is_system_device)

        if system_associated:
            return self._failed_result(target, "Target is associated with the running system and must not be overwritten.")

        if not authorized:
            return self._failed_result(target, "Destructive execution requires explicit authorization.")

        if self.dry_run:
            planned_size = profile.size_bytes or 0
            return SanitizationResult(
                status=SanitizationStatus.RUNNING,
                target_device=target,
                dry_run=True,
                message="Dry-run: HDD overwrite plan prepared without opening the device.",
                warnings=["Dry-run mode is enabled; no block writes were performed."],
                metadata={
                    "method": "HDD_OVERWRITE",
                    "device_type": "HDD",
                    "planned_size": planned_size,
                    "planned_method": "HDD_OVERWRITE",
                    "bytes_written": 0,
                    "total_bytes": planned_size,
                    "duration_seconds": 0.0,
                    "throughput": 0.0,
                    "start_time": None,
                    "end_time": None,
                },
            )

        if not self._is_block_device(target):
            return self._failed_result(target, "Target is not a block device and cannot be overwritten safely.")

        return self._execute_overwrite(target, profile)

    def _target_matches_profile(self, target: str, profile: DeviceProfile) -> bool:
        if not target or not profile.device_path:
            return False
        return self._normalize_device_path(target) == self._normalize_device_path(profile.device_path)

    def _normalize_device_path(self, path: str) -> str:
        return str(path).strip().rstrip("/")

    def _is_block_device(self, target: str) -> bool:
        try:
            if not target or not str(target).strip():
                return False

            candidate = str(target).strip()
            if candidate.startswith("/dev/"):
                return True

            if os.path.isdir(candidate):
                return False

            if not os.path.exists(candidate):
                return False

            mode = os.stat(candidate).st_mode
            return stat.S_ISBLK(mode)
        except (OSError, ValueError):
            return False

    def _execute_overwrite(self, target: str, profile: DeviceProfile) -> SanitizationResult:
        total_bytes = int(profile.size_bytes or 0)
        if total_bytes <= 0:
            return self._failed_result(target, "HDD target has no measurable size; write cannot proceed safely.")

        bytes_written = 0
        start_time = time.monotonic()
        chunk = b"\x00" * self.chunk_size

        try:
            with open(target, "r+b", buffering=0) as device:
                while bytes_written < total_bytes:
                    remaining = total_bytes - bytes_written
                    chunk_slice = min(self.chunk_size, remaining)
                    written = device.write(chunk[:chunk_slice])
                    if written != chunk_slice:
                        raise OSError(f"Short write: requested {chunk_slice}, wrote {written} bytes.")
                    bytes_written += written
                    elapsed = time.monotonic() - start_time
                    percentage = (bytes_written / total_bytes) * 100 if total_bytes else 0.0
                    throughput = (bytes_written / elapsed) if elapsed > 0 else 0.0
                    self._report_progress(
                        HDDOverwriteProgress(
                            bytes_written=bytes_written,
                            total_bytes=total_bytes,
                            percentage=percentage,
                            elapsed_seconds=elapsed,
                            throughput=throughput,
                        )
                    )
                device.flush()
                try:
                    fileno = device.fileno()
                except (AttributeError, OSError, ValueError):
                    fileno = None
                if fileno is not None:
                    try:
                        os.fsync(fileno)
                    except OSError:
                        pass
        except PermissionError as exc:
            return self._failed_result(target, f"Permission denied while writing HDD: {exc}")
        except OSError as exc:
            return self._failed_result(target, f"I/O failure while overwriting HDD: {exc}")
        except InterruptedError as exc:
            return self._failed_result(target, f"Operation interrupted while overwriting HDD: {exc}")

        elapsed = time.monotonic() - start_time
        throughput = (bytes_written / elapsed) if elapsed > 0 else 0.0
        return SanitizationResult(
            status=SanitizationStatus.RUNNING,
            target_device=target,
            dry_run=False,
            message="HDD overwrite executed to completion.",
            metadata={
                "method": "HDD_OVERWRITE",
                "device_type": "HDD",
                "bytes_written": bytes_written,
                "total_bytes": total_bytes,
                "duration_seconds": elapsed,
                "throughput": throughput,
                "start_time": start_time,
                "end_time": time.monotonic(),
            },
        )

    def _report_progress(self, progress: HDDOverwriteProgress) -> None:
        if self.progress_callback is not None:
            self.progress_callback(progress)
