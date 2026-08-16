from __future__ import annotations

import time
from typing import Any, Sequence

from agent.command_runner import CommandExecutor, CommandResult, SubprocessCommandExecutor
from agent.common import SanitizationResult, SanitizationStatus
from agent.pathways.base import SanitizationPathway
from agent.profiler import DeviceProfile


class ATAErasePathway(SanitizationPathway):
    def __init__(
        self,
        *,
        dry_run: bool = True,
        command_executor: CommandExecutor | None = None,
        timeout: float = 30.0,
    ) -> None:
        super().__init__(dry_run=dry_run, command_executor=command_executor)
        self.command_executor = command_executor or SubprocessCommandExecutor()
        self.timeout = float(timeout)

    def execute(
        self,
        target: str,
        *,
        profile: DeviceProfile | None = None,
        authorized: bool = False,
        system_associated: bool | None = None,
        password: str | None = None,
    ) -> SanitizationResult:
        if not target or not str(target).strip():
            return self._failed_result(target, "No target device was provided.")

        if profile is None:
            return self._failed_result(target, "A DeviceProfile is required before ATA erase execution.")

        if not self._target_matches_profile(target, profile):
            return self._failed_result(target, "Target identity does not match the provided profile.")

        if profile.device_type not in {"HDD", "SATA SSD", "SATA_SSD", "SSD"}:
            return self._unsupported_result(target, f"ATA erase is only valid for ATA/SATA HDD or SATA SSD devices; got {profile.device_type!r}.")

        security = self._security_capabilities(profile)
        if not security.get("supported"):
            return self._unsupported_result(target, "ATA security erase capability is not present on the target device.")

        state = self._read_security_state(target, profile)
        if state.get("frozen") is True:
            return SanitizationResult(
                status=SanitizationStatus.UNSUPPORTED,
                target_device=target,
                dry_run=self.dry_run,
                message="ATA security is frozen; the device requires manual unlock or hardware-appropriate power-cycle handling before secure erase can proceed.",
                errors=[
                    {
                        "code": "ATA_DEVICE_FROZEN",
                        "message": "ATA security is frozen and the common safe procedure is manual unlock or power cycle according to the hardware environment.",
                        "details": None,
                    }
                ],
                warnings=["ATA security is present but the device is frozen; automatic bypass is not permitted."],
                metadata={
                    "method": "ATA_ERASE",
                    "device_type": profile.device_type,
                    "security_supported": bool(security.get("supported")),
                    "security_frozen_before": True,
                    "erase_command_completed": False,
                    "security_state": state,
                },
            )

        if system_associated is None:
            system_associated = bool(profile.is_system_device)
        if system_associated:
            return self._failed_result(target, "Target is associated with the running system and must not be overwritten with ATA secure erase.")

        if not authorized:
            return self._failed_result(target, "ATA secure erase requires explicit authorization.")

        if self.dry_run:
            planned_commands = [
                self._redact_command(["hdparm", "-I", target]),
                self._redact_command(["hdparm", "--user-master", "u", "--security-set-pass", "<password>", target]),
                self._redact_command(["hdparm", "--user-master", "u", "--security-erase-prepare", target]),
                self._redact_command(["hdparm", "--user-master", "u", "--security-erase", "<password>", target]),
            ]
            return SanitizationResult(
                status=SanitizationStatus.RUNNING,
                target_device=target,
                dry_run=True,
                message="Dry-run: ATA secure erase plan prepared without modifying the device.",
                warnings=["Dry-run mode is enabled; no ATA password was set and no erase was executed."],
                metadata={
                    "method": "ATA_ERASE",
                    "device_type": profile.device_type,
                    "security_supported": bool(security.get("supported")),
                    "security_frozen_before": bool(state.get("frozen")),
                    "erase_command_completed": False,
                    "planned_commands": planned_commands,
                    "start_time": None,
                    "end_time": None,
                    "duration_seconds": 0.0,
                },
            )

        if not password:
            return self._failed_result(target, "ATA secure erase requires a password to be supplied by the caller.")

        start = time.monotonic()
        step_state: dict[str, Any] = {
            "security_supported": bool(security.get("supported")),
            "security_frozen_before": bool(state.get("frozen")),
            "erase_command_completed": False,
        }
        post_status: CommandResult | None = None

        try:
            set_pass_result = self.command_executor.run(["hdparm", "--user-master", "u", "--security-set-pass", password, target], timeout=self.timeout)
            if not set_pass_result.success:
                return self._failed_result(target, self._format_command_failure("security-set-pass", set_pass_result, "ATA security password setup failed.", password))

            prepare_result = self.command_executor.run(["hdparm", "--user-master", "u", "--security-erase-prepare", target], timeout=self.timeout)
            if not prepare_result.success:
                return self._failed_result(target, self._format_command_failure("security-erase-prepare", prepare_result, "ATA security erase prepare failed; security erase was not executed.", password))

            erase_result = self.command_executor.run(["hdparm", "--user-master", "u", "--security-erase", password, target], timeout=self.timeout)
            if not erase_result.success:
                return self._failed_result(target, self._format_command_failure("security-erase", erase_result, "ATA secure erase failed.", password))

            step_state["erase_command_completed"] = True
            post_status = self.command_executor.run(["hdparm", "-I", target], timeout=self.timeout)
        except FileNotFoundError as exc:
            return self._failed_result(target, f"ATA command is unavailable on this system: {exc}")
        except PermissionError as exc:
            return self._failed_result(target, f"Permission denied while issuing ATA secure erase: {exc}")
        except TimeoutError as exc:
            return self._failed_result(target, f"ATA secure erase timeout: {exc}")
        except InterruptedError as exc:
            return self._failed_result(target, f"ATA secure erase was interrupted: {exc}")
        except OSError as exc:
            return self._failed_result(target, f"I/O failure while issuing ATA secure erase: {exc}")

        end = time.monotonic()
        elapsed = max(0.0, end - start)
        post_text = (post_status.stdout or "") if post_status is not None else ""
        metadata: dict[str, Any] = {
            "method": "ATA_ERASE",
            "device": target,
            "device_type": profile.device_type,
            "start_time": start,
            "end_time": end,
            "duration_seconds": elapsed,
            "status": SanitizationStatus.RUNNING.value,
            "security_supported": bool(security.get("supported")),
            "security_frozen_before": bool(state.get("frozen")),
            "erase_command_completed": bool(step_state.get("erase_command_completed")),
            "post_status": post_text,
        }

        return SanitizationResult(
            status=SanitizationStatus.RUNNING,
            target_device=target,
            dry_run=False,
            message="ATA secure erase commands were issued; verification remains separate.",
            warnings=["ATA secure erase has been initiated but is not yet marked verified."],
            errors=[],
            metadata=metadata,
        )

    def _target_matches_profile(self, target: str, profile: DeviceProfile) -> bool:
        if not target or not profile.device_path:
            return False
        return self._normalize_device_path(target) == self._normalize_device_path(profile.device_path)

    def _normalize_device_path(self, path: str) -> str:
        return str(path).strip().rstrip("/")

    def _security_capabilities(self, profile: DeviceProfile) -> dict[str, Any]:
        capability_section = profile.capabilities.get("security") or {}
        if not isinstance(capability_section, dict):
            return {}
        return {
            "supported": bool(capability_section.get("supported") or capability_section.get("secure_erase_supported")),
            "frozen": bool(capability_section.get("frozen")),
            "secure_erase_supported": bool(capability_section.get("secure_erase_supported")),
        }

    def _read_security_state(self, target: str, profile: DeviceProfile) -> dict[str, Any]:
        security = profile.capabilities.get("security") or {}
        if isinstance(security, dict):
            state = {
                "supported": bool(security.get("supported") or security.get("secure_erase_supported")),
                "frozen": bool(security.get("frozen")),
                "raw": security.get("raw_output"),
            }
            if state.get("supported") or state.get("frozen") is not None:
                return state

        try:
            result = self.command_executor.run(["hdparm", "-I", target], timeout=self.timeout)
        except FileNotFoundError:
            return {"supported": False, "frozen": False, "raw": None, "query_error": "hdparm command not available"}

        if not result:
            return {"supported": False, "frozen": False, "raw": None, "query_error": "no status output"}

        output = (result.stdout or "") + (result.stderr or "")
        lowered = output.lower()
        return {
            "supported": bool("security:" in lowered or "security support" in lowered or "enhanced secure erase" in lowered),
            "frozen": "security: frozen" in lowered or "frozen" in lowered and "not frozen" not in lowered,
            "raw": output.strip(),
        }

    def _format_command_failure(self, command_name: str, result: CommandResult | None, default: str, password: str | None = None) -> str:
        if result is None:
            return default
        output = result.stderr or result.stdout or "unknown ATA command failure"
        redacted = self._sanitize_text(output, password)
        return f"{default} ({command_name} failed: {redacted})"

    def _sanitize_text(self, text: str, password: str | None = None) -> str:
        if not text:
            return ""
        sanitized = text.replace("\r", " ")
        if password:
            sanitized = sanitized.replace(password, "<redacted>")
        return sanitized

    def _redact_command(self, command: Sequence[str]) -> list[str]:
        redacted = []
        for index, item in enumerate(command):
            if index >= 2 and item and isinstance(item, str):
                if item in {"--security-set-pass", "--security-erase", "--security-erase-prepare"}:
                    redacted.append(item)
                    continue
                if index in {4, 5} and "password" not in command[3].lower() and command[0] == "hdparm":
                    redacted.append("<redacted>")
                    continue
            redacted.append(item)
        if redacted and redacted[0] == "hdparm" and redacted[1] == "--user-master" and redacted[2] == "u":
            for idx in range(len(redacted)):
                if redacted[idx] in {"--security-set-pass", "--security-erase"} and idx + 1 < len(redacted):
                    redacted[idx + 1] = "<redacted>"
        return redacted
