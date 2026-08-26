from __future__ import annotations

import random
import time
from dataclasses import dataclass, field
from typing import Any

from agent.command_runner import CommandExecutor, SubprocessCommandExecutor
from agent.nvme_status import parse_sanitize_log, sanitize_log_command
from .common import SanitizationStatus


@dataclass(slots=True)
class VerificationResult:
    status: SanitizationStatus
    device: str = ""
    pathway: str = ""
    verified: bool = False
    verification_time: float | None = None
    samples_checked: int = 0
    samples_passed: int = 0
    samples_failed: int = 0
    bytes_checked: int = 0
    message: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    details: str | None = None

    def __post_init__(self) -> None:
        if self.details is None and self.evidence:
            source = self.evidence.get("source", "unknown")
            status = self.evidence.get("status", "unknown")
            self.details = f"verification source={source}, status={status}"
        if not self.message and self.details:
            self.message = self.details


def _normalize_pathway(pathway: str | None) -> str:
    if pathway is None:
        return ""
    return str(pathway).strip().upper().replace("-", "_")


class Verifier:
    def __init__(
        self,
        *,
        dry_run: bool = True,
        command_executor: CommandExecutor | None = None,
        sample_count: int = 8,
        sample_size: int = 4096,
        timeout: float = 10.0,
    ) -> None:
        self.dry_run = dry_run
        self.command_executor = command_executor or SubprocessCommandExecutor()
        self.sample_count = max(1, int(sample_count))
        self.sample_size = max(1, int(sample_size))
        self.timeout = float(timeout)

    def verify(
        self,
        *,
        result: str | None = None,
        device: str | None = None,
        pathway: str | None = None,
        profile=None,
        sanitization_result: Any | None = None,
    ) -> VerificationResult:
        started = time.monotonic()

        if result is not None and device is None and pathway is None and profile is None:
            verification = VerificationResult(
                status=SanitizationStatus.VERIFIED,
                device=device or "",
                pathway=pathway or "",
                verified=True,
                verification_time=time.monotonic() - started,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message=result,
                evidence={"source": "legacy", "status": "verified"},
                warnings=[],
                errors=[],
                limitations=[],
                metadata={},
                details=result,
            )
            verification.verification_time = time.monotonic() - started
            return verification

        route = _normalize_pathway(pathway)
        device_name = str(device or "").strip()

        if route == "HDD_OVERWRITE":
            verification = self._verify_hdd_overwrite(device_name, profile)
        elif route in {"ATA_ERASE", "ATA_SECURE_ERASE"}:
            verification = self._verify_ata_erase(device_name, profile)
        elif route in {"CRYPTO_ERASE", "NVME_CRYPTO_ERASE"}:
            verification = self._verify_nvme(device_name, profile, "CRYPTO_ERASE", sanitization_result)
        elif route in {"BLOCK_ERASE", "NVME_BLOCK_ERASE"}:
            verification = self._verify_nvme(device_name, profile, "BLOCK_ERASE", sanitization_result)
        elif route in {"NVME_OVERWRITE", "OVERWRITE"}:
            verification = self._verify_nvme(device_name, profile, "OVERWRITE", sanitization_result)
        else:
            verification = VerificationResult(
                status=SanitizationStatus.UNSUPPORTED,
                device=device_name,
                pathway=route,
                verified=False,
                verification_time=time.monotonic() - started,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="Unknown pathway; verification is unsupported.",
                evidence={"source": "routing", "status": "unsupported", "pathway": route},
                warnings=["Unknown sanitization pathway; no verification route is defined."],
                errors=[],
                limitations=["No read-only verification strategy is available for the requested pathway."],
                metadata={"pathway": route},
                details="Unknown pathway; verification is unsupported.",
            )

        verification.verification_time = time.monotonic() - started
        return verification

    def _verify_hdd_overwrite(self, device: str, profile: Any) -> VerificationResult:
        if profile is None:
            return VerificationResult(
                status=SanitizationStatus.INCONCLUSIVE,
                device=device,
                pathway="HDD_OVERWRITE",
                verified=False,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="HDD verification is inconclusive because the device profile is missing.",
                evidence={"source": "hdd_zero_sampling", "status": "inconclusive"},
                warnings=["No profile metadata was supplied for HDD overwrite verification."],
                errors=["Insufficient metadata for read-only sampling verification."],
                limitations=["Verification cannot assess the device without profile size metadata."],
                metadata={"source": "hdd_zero_sampling", "status": "inconclusive"},
                details="HDD verification is inconclusive because the device profile is missing.",
            )

        size_bytes = int(profile.size_bytes or 0)
        if size_bytes <= 0:
            return VerificationResult(
                status=SanitizationStatus.INCONCLUSIVE,
                device=device,
                pathway="HDD_OVERWRITE",
                verified=False,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="HDD verification is inconclusive because the device size is unknown.",
                evidence={"source": "hdd_zero_sampling", "status": "inconclusive"},
                warnings=["Device size metadata is missing or invalid."],
                errors=["Insufficient device size data for read-only sampling."],
                limitations=["Verification is limited to sampled evidence because absolute disk coverage is not available."],
                metadata={"source": "hdd_zero_sampling", "status": "inconclusive"},
                details="HDD verification is inconclusive because the device size is unknown.",
            )

        if size_bytes < self.sample_size:
            return VerificationResult(
                status=SanitizationStatus.INCONCLUSIVE,
                device=device,
                pathway="HDD_OVERWRITE",
                verified=False,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="HDD verification is inconclusive because the device is too small for the configured sample size.",
                evidence={"source": "hdd_zero_sampling", "status": "insufficient_data"},
                warnings=["Device is smaller than the configured sample size; insufficient data for meaningful verification."],
                errors=[],
                limitations=["Verification is based on a small device footprint and cannot establish full-disk coverage."],
                metadata={"source": "hdd_zero_sampling", "status": "insufficient_data"},
                details="HDD verification is inconclusive because the device is too small for the configured sample size.",
            )

        offsets = self._sample_offsets(size_bytes, self.sample_count, self.sample_size)
        samples_checked = 0
        samples_passed = 0
        samples_failed = 0
        bytes_checked = 0
        errors: list[str] = []

        try:
            with open(device, "rb") as handle:
                for offset in offsets:
                    samples_checked += 1
                    handle.seek(offset, 0)
                    sample = handle.read(self.sample_size)
                    bytes_checked += len(sample)
                    if len(sample) < self.sample_size:
                        samples_failed += 1
                        errors.append(f"Short read while sampling at offset {offset}: expected {self.sample_size}, got {len(sample)} bytes.")
                        continue

                    if sample == b"\x00" * len(sample):
                        samples_passed += 1
                    else:
                        samples_failed += 1
                        errors.append(f"Non-zero bytes observed while sampling offset {offset}.")
        except OSError as exc:
            return VerificationResult(
                status=SanitizationStatus.FAILED,
                device=device,
                pathway="HDD_OVERWRITE",
                verified=False,
                verification_time=0.0,
                samples_checked=samples_checked,
                samples_passed=samples_passed,
                samples_failed=samples_failed,
                bytes_checked=bytes_checked,
                message="HDD verification failed because the read-only verification sample could not be read.",
                evidence={"source": "hdd_zero_sampling", "status": "failed", "error": str(exc)},
                warnings=[],
                errors=[f"Read failure while sampling HDD zero pattern: {exc}"],
                limitations=["Verification is based on sampled zero pattern reading only; it cannot prove the entire disk is sanitized."],
                metadata={"source": "hdd_zero_sampling", "status": "failed", "error": str(exc)},
                details="HDD verification failed because the read-only verification sample could not be read.",
            )

        if samples_failed > 0:
            return VerificationResult(
                status=SanitizationStatus.FAILED,
                device=device,
                pathway="HDD_OVERWRITE",
                verified=False,
                verification_time=0.0,
                samples_checked=samples_checked,
                samples_passed=samples_passed,
                samples_failed=samples_failed,
                bytes_checked=bytes_checked,
                message="HDD verification failed because at least one sampled read contained non-zero bytes.",
                evidence={
                    "source": "hdd_zero_sampling",
                    "status": "failed",
                    "samples_checked": samples_checked,
                    "samples_passed": samples_passed,
                    "samples_failed": samples_failed,
                    "bytes_checked": bytes_checked,
                },
                warnings=[],
                errors=errors,
                limitations=["Verification is based on sampled zero pattern checks and does not prove every physical sector is zero-filled."],
                metadata={
                    "source": "hdd_zero_sampling",
                    "status": "failed",
                    "samples_checked": samples_checked,
                    "samples_passed": samples_passed,
                    "samples_failed": samples_failed,
                    "bytes_checked": bytes_checked,
                },
                details="HDD verification failed because at least one sampled read contained non-zero bytes.",
            )

        return VerificationResult(
            status=SanitizationStatus.VERIFIED,
            device=device,
            pathway="HDD_OVERWRITE",
            verified=True,
            verification_time=0.0,
            samples_checked=samples_checked,
            samples_passed=samples_passed,
            samples_failed=samples_failed,
            bytes_checked=bytes_checked,
            message="HDD verification observed zero-filled samples; this is evidence, not absolute proof of full physical sanitization.",
            evidence={
                "source": "hdd_zero_sampling",
                "status": "verified",
                "samples_checked": samples_checked,
                "samples_passed": samples_passed,
                "samples_failed": samples_failed,
                "bytes_checked": bytes_checked,
            },
            warnings=["Sampled read-only verification confirms the observed zero pattern, but does not prove every physical sector contains zeros."],
            errors=[],
            limitations=["Verification is evidence-based sampling only and not a full physical-sector guarantee."],
            metadata={
                "source": "hdd_zero_sampling",
                "status": "verified",
                "samples_checked": samples_checked,
                "samples_passed": samples_passed,
                "samples_failed": samples_failed,
                "bytes_checked": bytes_checked,
            },
            details="HDD verification observed zero-filled samples; this is evidence, not absolute proof of full physical sanitization.",
        )

    def _verify_ata_erase(self, device: str, profile: Any) -> VerificationResult:
        if profile is None:
            return VerificationResult(
                status=SanitizationStatus.INCONCLUSIVE,
                device=device,
                pathway="ATA_ERASE",
                verified=False,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="ATA verification is inconclusive because the device profile is missing.",
                evidence={"source": "hdparm", "status": "inconclusive"},
                warnings=["No profile metadata is available for ATA erase verification."],
                errors=["ATA verification requires read-only capability metadata or hdparm output."],
                limitations=["ATA security state cannot confirm every physical sector was erased."],
                metadata={"source": "hdparm", "status": "inconclusive"},
                details="ATA verification is inconclusive because the device profile is missing.",
            )

        try:
            result = self.command_executor.run(["hdparm", "-I", device], timeout=self.timeout)
        except FileNotFoundError:
            return VerificationResult(
                status=SanitizationStatus.FAILED,
                device=device,
                pathway="ATA_ERASE",
                verified=False,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="ATA verification failed because hdparm is unavailable.",
                evidence={"source": "hdparm", "status": "failed", "error": "hdparm not available"},
                warnings=[],
                errors=["hdparm is not available for ATA read-only verification."],
                limitations=["ATA verification could not run because the required command is unavailable."],
                metadata={"source": "hdparm", "status": "failed", "error": "hdparm not available"},
                details="ATA verification failed because hdparm is unavailable.",
            )

        if not result.success:
            return VerificationResult(
                status=SanitizationStatus.FAILED,
                device=device,
                pathway="ATA_ERASE",
                verified=False,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="ATA verification failed because the ATA status command did not succeed.",
                evidence={"source": "hdparm", "status": "failed", "stderr": result.stderr or result.stdout or "unknown"},
                warnings=[],
                errors=[f"ATA verification command failed: {result.stderr or result.stdout or 'unknown error'}"],
                limitations=["Read-only ATA status output failed; no verification claim is made."],
                metadata={"source": "hdparm", "status": "failed", "stderr": result.stderr or result.stdout or "unknown"},
                details="ATA verification failed because the ATA status command did not succeed.",
            )

        output = (result.stdout or "") + (result.stderr or "")
        lowered = output.lower()
        if not output.strip():
            return VerificationResult(
                status=SanitizationStatus.INCONCLUSIVE,
                device=device,
                pathway="ATA_ERASE",
                verified=False,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="ATA verification is inconclusive because the command produced no usable output.",
                evidence={"source": "hdparm", "status": "unknown"},
                warnings=["ATA verification output was empty; no evidence of final state was returned."],
                errors=[],
                limitations=["A blank ATA status report does not establish successful sanitization."],
                metadata={"source": "hdparm", "status": "unknown"},
                details="ATA verification is inconclusive because the command produced no usable output.",
            )

        security_supported = "security:" in lowered or "security support" in lowered or "enhanced secure erase" in lowered
        security_disabled = "security: disabled" in lowered or "security disabled" in lowered
        security_enabled = "security: enabled" in lowered or "security enabled" in lowered
        frozen = "security: frozen" in lowered or ("frozen" in lowered and "not frozen" not in lowered)

        if not security_supported:
            return VerificationResult(
                status=SanitizationStatus.INCONCLUSIVE,
                device=device,
                pathway="ATA_ERASE",
                verified=False,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="ATA verification is inconclusive because the status output does not clearly show ATA secure erase capability.",
                evidence={"source": "hdparm", "status": "unknown", "raw": output.strip()},
                warnings=["ATA capability information was not recognized in the status output."],
                errors=[],
                limitations=["ATA verification depends on the security capability reporting being present and interpretable."],
                metadata={"source": "hdparm", "status": "unknown", "raw": output.strip()},
                details="ATA verification is inconclusive because the status output does not clearly show ATA secure erase capability.",
            )

        if security_enabled or frozen:
            return VerificationResult(
                status=SanitizationStatus.FAILED,
                device=device,
                pathway="ATA_ERASE",
                verified=False,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="ATA verification failed because the device still reports a security state inconsistent with a completed secure erase.",
                evidence={"source": "hdparm", "status": "unexpected_state", "raw": output.strip()},
                warnings=["ATA security is still enabled or frozen, which does not constitute verified completion."],
                errors=["ATA verification observed an unexpected security state."],
                limitations=["A security-enabled or frozen state does not prove any physical blocks were erased."],
                metadata={"source": "hdparm", "status": "unexpected_state", "raw": output.strip()},
                details="ATA verification failed because the device still reports a security state inconsistent with a completed secure erase.",
            )

        if security_disabled:
            return VerificationResult(
                status=SanitizationStatus.VERIFIED,
                device=device,
                pathway="ATA_ERASE",
                verified=True,
                verification_time=0.0,
                samples_checked=0,
                samples_passed=0,
                samples_failed=0,
                bytes_checked=0,
                message="ATA verification observed the secure erase state as disabled and not frozen; this is only evidence of the device-reported post-operation state.",
                evidence={"source": "hdparm", "status": "security_disabled", "raw": output.strip()},
                warnings=["ATA secure erase status is disabled and unfrozen, but this is evidence of the device state rather than a guarantee of every physical sector."],
                errors=[],
                limitations=["ATA security state is evidence only; it does not guarantee every physical sector was erased."],
                metadata={"source": "hdparm", "status": "security_disabled", "raw": output.strip()},
                details="ATA verification observed the secure erase state as disabled and not frozen; this is only evidence of the device-reported post-operation state.",
            )

        return VerificationResult(
            status=SanitizationStatus.INCONCLUSIVE,
            device=device,
            pathway="ATA_ERASE",
            verified=False,
            verification_time=0.0,
            samples_checked=0,
            samples_passed=0,
            samples_failed=0,
            bytes_checked=0,
            message="ATA verification is inconclusive because the output does not clearly confirm the expected final state.",
            evidence={"source": "hdparm", "status": "unknown", "raw": output.strip()},
            warnings=["ATA verification output did not clearly indicate a successful or failed post-operation state."],
            errors=[],
            limitations=["ATA verification requires a clear device-reported state to support a verification claim."],
            metadata={"source": "hdparm", "status": "unknown", "raw": output.strip()},
            details="ATA verification is inconclusive because the output does not clearly confirm the expected final state.",
        )

    def _verify_nvme(self, device: str, profile: Any, method: str, sanitization_result: Any | None = None) -> VerificationResult:
        execution_metadata = getattr(sanitization_result, "metadata", {}) if sanitization_result is not None else {}
        execution_metadata = execution_metadata if isinstance(execution_metadata, dict) else {}
        verification_target = str(execution_metadata.get("sanitize_target") or device)
        if execution_metadata and (
            execution_metadata.get("requested_namespace") != device
            or execution_metadata.get("resolved_controller") != verification_target
            or execution_metadata.get("sanitize_scope") != "controller"
        ):
            return self._nvme_result(
                SanitizationStatus.INCONCLUSIVE, device, method, "scope_mismatch",
                "NVMe verification is inconclusive because execution scope metadata is inconsistent.",
                [], ["Namespace/controller execution metadata did not bind to the requested asset."],
                ["Verification refuses to query a controller not bound to the selected namespace."],
                {"verification_target": verification_target},
            )
        try:
            result = self.command_executor.run(sanitize_log_command(verification_target), timeout=self.timeout)
        except FileNotFoundError:
            return self._nvme_result(
                SanitizationStatus.FAILED, device, method, "failed", "NVMe verification failed because nvme-cli is unavailable.",
                [], ["nvme-cli is unavailable for read-only NVMe verification."],
                ["Verification cannot proceed without access to the device's sanitize log."], {},
            )
        except TimeoutError as exc:
            return self._nvme_result(
                SanitizationStatus.INCONCLUSIVE, device, method, "timeout", "NVMe verification is inconclusive because sanitize-log timed out.",
                ["The read-only sanitize-log command timed out."], [],
                ["A sanitize-log timeout is not evidence of successful completion."], {"error": str(exc)},
            )
        except (PermissionError, OSError, InterruptedError) as exc:
            return self._nvme_result(
                SanitizationStatus.FAILED, device, method, "failed", "NVMe verification failed because sanitize-log could not be read.",
                [], [f"NVMe sanitize-log polling failed: {exc}"],
                ["Verification cannot proceed without a readable sanitize log."], {"error": str(exc)},
            )

        output = ((result.stdout or "") + (result.stderr or "")).strip()
        if not result.success:
            return self._nvme_result(
                SanitizationStatus.FAILED, device, method, "failed", "NVMe verification failed because the sanitize-log command did not succeed.",
                [], [f"NVMe sanitize log failed: {output or 'unknown error'}"],
                ["No verification result is claimed when the sanitize-log command fails."], {"raw": output},
            )

        parsed = parse_sanitize_log(output)
        if parsed is None:
            return self._nvme_result(
                SanitizationStatus.INCONCLUSIVE, device, method, "unknown", "NVMe verification is inconclusive because sanitize-log JSON did not contain a valid SSTAT value.",
                ["The NVMe sanitize log did not provide a parseable structured SSTAT value."], [],
                ["Only a controller-reported successful SSTAT can support a VERIFIED result."], {"raw": output, "verification_target": verification_target},
            )

        observed = parsed["status"]
        if observed == "COMPLETED":
            return self._nvme_result(
                SanitizationStatus.VERIFIED, device, method, "completed", "NVMe verification observed controller-reported successful sanitize completion.",
                ["Controller-reported completion is evidence of success, not a guarantee of every physical sector."], [],
                ["Verification is based on controller-reported sanitize completion and does not prove every physical sector was sanitized.", "The sanitize-log JSON interface does not provide a documented stable field for validating the requested sanitize action.", "The parsed global_data_erased bit is recorded as evidence only and is not used to validate the requested sanitize method."], {**parsed, "verification_target": verification_target, "requested_namespace": device},
            )
        if observed == "IN_PROGRESS":
            return self._nvme_result(
                SanitizationStatus.INCONCLUSIVE, device, method, "in_progress", "NVMe verification is inconclusive because SSTAT reports sanitize in progress.",
                ["The sanitize operation is still reported as in progress."], [],
                ["In-progress SSTAT is not evidence of successful completion."], parsed,
            )
        if observed in {"FAILED", "ABORTED"}:
            return self._nvme_result(
                SanitizationStatus.FAILED, device, method, observed.lower(), f"NVMe verification failed because SSTAT reports {observed.lower()}.",
                [], [f"The NVMe sanitize log reports {observed.lower()}."],
                ["A failed or aborted sanitize state is not successful completion."], parsed,
            )
        return self._nvme_result(
            SanitizationStatus.INCONCLUSIVE, device, method, "invalid", "NVMe verification is inconclusive because SSTAT is invalid or unsupported.",
            ["The NVMe sanitize log returned an invalid or unsupported SSTAT value."], [],
            ["An invalid SSTAT cannot support a VERIFIED result."], parsed,
        )

    def _nvme_result(
        self,
        status: SanitizationStatus,
        device: str,
        method: str,
        result_status: str,
        message: str,
        warnings: list[str],
        errors: list[str],
        limitations: list[str],
        metadata: dict[str, Any],
    ) -> VerificationResult:
        evidence = {"source": "nvme_sanitize_log", "status": result_status, **metadata}
        return VerificationResult(
            status=status, device=device, pathway=method, verified=status == SanitizationStatus.VERIFIED,
            verification_time=0.0, message=message, evidence=evidence, warnings=warnings,
            errors=errors, limitations=limitations, metadata=evidence, details=message,
        )

    def _sample_offsets(self, total_size: int, sample_count: int, sample_size: int) -> list[int]:
        if total_size <= 0:
            return []
        limit = max(1, total_size - sample_size)
        seed = random.Random(0xC0FFEE)
        offsets = []
        for _ in range(sample_count):
            offsets.append(seed.randint(0, limit))
        return offsets
