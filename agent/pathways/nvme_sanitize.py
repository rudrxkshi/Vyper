from __future__ import annotations

import time
from typing import Any, Sequence

from agent.command_runner import CommandExecutor, CommandResult, SubprocessCommandExecutor
from agent.common import SanitizationResult, SanitizationStatus
from agent.nvme_status import parse_sanitize_log, sanitize_log_command
from agent.pathways.base import SanitizationPathway
from agent.profiler import DeviceProfile


class NVMeSanitizePathway(SanitizationPathway):
    def __init__(
        self,
        *,
        dry_run: bool = True,
        command_executor: CommandExecutor | None = None,
        timeout: float = 30.0,
        poll_interval: float = 1.0,
    ) -> None:
        super().__init__(dry_run=dry_run, command_executor=command_executor)
        self.command_executor = command_executor or SubprocessCommandExecutor()
        self.timeout = float(timeout)
        self.poll_interval = float(poll_interval)

    def execute(
        self,
        target: str,
        *,
        profile: DeviceProfile | None = None,
        authorized: bool = False,
        system_associated: bool | None = None,
        selected_method: str | None = None,
    ) -> SanitizationResult:
        if not target or not str(target).strip():
            return self._failed_result(target, "No target device was provided.")

        if profile is None:
            return self._failed_result(target, "A DeviceProfile is required before NVMe sanitize execution.")

        if not self._target_matches_profile(target, profile):
            return self._failed_result(target, "Target identity does not match the provided profile.")

        if profile.device_type != "NVMe":
            return self._unsupported_result(target, f"NVMe sanitization is only valid for NVMe devices; got {profile.device_type!r}.")

        method = self._canonical_method(selected_method) if selected_method is not None else self._select_method(profile)
        if method is None:
            message = (
                f"Unsupported NVMe sanitize method selected: {selected_method!r}."
                if selected_method is not None
                else "No supported NVMe sanitization capability is available on this device."
            )
            return self._unsupported_result(target, message)

        if system_associated is None:
            system_associated = bool(profile.is_system_device)
        if system_associated:
            return self._failed_result(target, "Target is associated with the running system and must not be sanitized.")

        if not authorized:
            return self._failed_result(target, "NVMe sanitize requires explicit authorization.")

        if self.dry_run:
            return SanitizationResult(
                status=SanitizationStatus.RUNNING,
                target_device=target,
                dry_run=True,
                message="Dry-run: NVMe sanitize plan prepared without issuing a destructive command.",
                warnings=["Dry-run mode is enabled; no NVMe sanitize command was executed."],
                metadata={
                    "method": "NVME_SANITIZE",
                    "device": target,
                    "device_type": "NVMe",
                    "sanitize_method": method,
                    "start_time": None,
                    "end_time": None,
                    "duration_seconds": 0.0,
                    "command_submitted": False,
                    "completion_status": "PLANNED",
                },
            )

        command = self._build_command(method, target)
        if command is None:
            return self._unsupported_result(target, f"Unsupported NVMe sanitize method: {method!r}.")

        start = time.monotonic()
        try:
            submission = self.command_executor.run(command, timeout=self.timeout)
        except FileNotFoundError as exc:
            return self._failed_result(target, f"nvme-cli is unavailable on this system: {exc}")
        except PermissionError as exc:
            return self._failed_result(target, f"Permission denied while issuing NVMe sanitize: {exc}")
        except TimeoutError as exc:
            return self._failed_result(target, f"NVMe sanitize timed out: {exc}")
        except InterruptedError as exc:
            return self._failed_result(target, f"NVMe sanitize was interrupted: {exc}")
        except OSError as exc:
            return self._failed_result(target, f"I/O failure while issuing NVMe sanitize: {exc}")

        if not submission.success:
            return self._failed_result(target, self._format_command_failure("sanitize", submission))

        status = self._poll_sanitize_status(target, method, start)
        end = time.monotonic()
        metadata = {
            "method": "NVME_SANITIZE",
            "device": target,
            "device_type": "NVMe",
            "sanitize_method": method,
            "start_time": start,
            "end_time": end,
            "duration_seconds": max(0.0, end - start),
            "command_submitted": True,
            "completion_status": status["status"],
        }

        if status["status"] == "COMPLETED":
            return SanitizationResult(
                status=SanitizationStatus.RUNNING,
                target_device=target,
                dry_run=False,
                message="NVMe sanitize command was accepted and the sanitize log reports completion; verification remains separate.",
                warnings=["NVMe sanitize has been started and reported completed, but it is not marked VERIFIED."],
                metadata=metadata,
            )

        if status["status"] == "FAILED":
            return SanitizationResult(
                status=SanitizationStatus.FAILED,
                target_device=target,
                dry_run=False,
                message=status["message"],
                metadata=metadata,
            )

        if status["status"] == "TIMEOUT":
            return SanitizationResult(
                status=SanitizationStatus.FAILED,
                target_device=target,
                dry_run=False,
                message=status["message"],
                metadata=metadata,
            )

        return SanitizationResult(
            status=SanitizationStatus.FAILED,
            target_device=target,
            dry_run=False,
            message=status["message"],
            metadata=metadata,
        )

    def _target_matches_profile(self, target: str, profile: DeviceProfile) -> bool:
        if not target or not profile.device_path:
            return False
        return self._normalize_device_path(target) == self._normalize_device_path(profile.device_path)

    def _normalize_device_path(self, path: str) -> str:
        return str(path).strip().rstrip("/")

    def _select_method(self, profile: DeviceProfile) -> str | None:
        sanicap = profile.capabilities.get("sanicap") or {}
        crypto_applicable = bool(profile.capabilities.get("crypto_erase_applicable", False))

        if self._bool_value(sanicap.get("crypto_erase")) and crypto_applicable:
            return "CRYPTO_ERASE"
        if self._bool_value(sanicap.get("block_erase")):
            return "BLOCK_ERASE"
        if self._bool_value(sanicap.get("overwrite")):
            return "OVERWRITE"
        if self._bool_value(profile.capabilities.get("crypto_erase_supported")) and crypto_applicable:
            return "CRYPTO_ERASE"
        if self._bool_value(profile.capabilities.get("block_erase_supported")):
            return "BLOCK_ERASE"
        if self._bool_value(profile.capabilities.get("overwrite_supported")):
            return "OVERWRITE"
        return None

    def _canonical_method(self, method: str | None) -> str | None:
        normalized = str(method or "").strip().upper()
        return {
            "CRYPTO_ERASE": "CRYPTO_ERASE",
            "BLOCK_ERASE": "BLOCK_ERASE",
            "NVME_OVERWRITE": "OVERWRITE",
            "OVERWRITE": "OVERWRITE",
        }.get(normalized)

    def _build_command(self, method: str, target: str) -> list[str] | None:
        sanact = {
            "CRYPTO_ERASE": "4",
            "BLOCK_ERASE": "2",
            "OVERWRITE": "3",
        }.get(method)
        if sanact is None:
            return None
        return ["nvme", "sanitize", target, "-a", sanact]

    def _poll_sanitize_status(self, target: str, method: str, start: float) -> dict[str, Any]:
        deadline = start + self.timeout
        last_status: dict[str, Any] | None = None
        while time.monotonic() <= deadline:
            try:
                result = self.command_executor.run(sanitize_log_command(target), timeout=self.timeout)
            except FileNotFoundError:
                return {"status": "FAILED", "message": "nvme-cli is unavailable while polling NVMe sanitize status."}
            except (PermissionError, OSError, TimeoutError, InterruptedError) as exc:
                return {"status": "FAILED", "message": f"NVMe sanitize polling failed: {exc}"}

            if not result.success:
                return {"status": "FAILED", "message": self._format_command_failure("sanitize-log", result)}

            parsed = parse_sanitize_log(result.stdout or result.stderr or "")
            if parsed is None:
                return {"status": "FAILED", "message": "Malformed NVMe sanitize-log output; unable to determine sanitize state."}

            last_status = parsed
            if parsed["status"] in {"COMPLETED", "FAILED", "ABORTED", "INVALID"}:
                parsed["message"] = self._status_message(parsed["status"])
                return parsed

            time.sleep(self.poll_interval)

        if last_status is not None:
            return {"status": "TIMEOUT", "message": "NVMe sanitize operation reached timeout while awaiting completion."}
        return {"status": "TIMEOUT", "message": "NVMe sanitize operation reached timeout before a valid status was reported."}

    def _status_message(self, status: str) -> str:
        return {
            "COMPLETED": "NVMe sanitize log reports successful completion.",
            "FAILED": "NVMe sanitize log reports failure.",
            "ABORTED": "NVMe sanitize log reports an aborted operation.",
            "INVALID": "NVMe sanitize log returned an invalid or unsupported status.",
        }.get(status, "NVMe sanitize is still in progress.")

    def _format_command_failure(self, command_name: str, result: CommandResult) -> str:
        output = result.stderr or result.stdout or "unknown NVMe command failure"
        sanitized = output.replace("\r", " ")
        return f"NVMe {command_name} failed: {sanitized}"

    def _bool_value(self, value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            return value.strip().lower() in {"1", "true", "yes", "y", "on"}
        return bool(value)
