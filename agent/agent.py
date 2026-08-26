from __future__ import annotations

import argparse
import hmac
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from vyper_version import __version__

from agent.certificate import CertificateBuilder, SanitizationCertificate
from agent.common import JobState, SanitizationResult, SanitizationStatus
from agent.credentials import AgentCredentialStore, authorization_api_key
from agent.evidence import EvidenceCollector, EvidenceRecord
from agent.nvme_scope import NVMeControllerResolver
from agent.pathways.ata_erase import ATAErasePathway
from agent.pathways.hdd_overwrite import HDDOverwritePathway
from agent.pathways.nvme_sanitize import NVMeSanitizePathway
from agent.policy import PolicyDecision, PolicyEngine
from agent.profiler import DeviceProfile, DeviceProfiler
from agent.verifier import VerificationResult, Verifier


@dataclass(slots=True)
class OrchestrationJobResult:
    job_state: JobState
    state_history: list[JobState] = field(default_factory=list)
    target: str = ""
    profile: DeviceProfile | None = None
    policy: PolicyDecision | None = None
    execution: SanitizationResult | None = None
    verification: VerificationResult | None = None
    evidence: EvidenceRecord | None = None
    certificate: SanitizationCertificate | None = None
    message: str = ""


class _ObservableStateHistory(list[JobState]):
    def __init__(self, initial: list[JobState], callback: Callable[[JobState], None] | None) -> None:
        super().__init__(initial)
        self.callback = callback

    def append(self, state: JobState) -> None:
        super().append(state)
        if self.callback is not None:
            self.callback(state)

    def extend(self, states) -> None:
        for state in states:
            self.append(state)


class VYPERAgent:
    def __init__(
        self,
        *,
        dry_run: bool = False,
        profiler: DeviceProfiler | None = None,
        policy_engine: PolicyEngine | None = None,
        verifier: Verifier | None = None,
        evidence_collector: EvidenceCollector | None = None,
        certificate_builder: CertificateBuilder | None = None,
<<<<<<< HEAD
        credential_store: AgentCredentialStore | None = None,
        api_key_required: bool = False,
        expected_api_key: str | None = None,
=======
        nvme_scope_resolver: Callable[[str], dict[str, Any]] | None = None,
>>>>>>> f92af61deccff4855c25365623da795ea1595f4a
    ) -> None:
        self.dry_run = dry_run
        self.profiler = profiler or DeviceProfiler(dry_run=dry_run)
        self.policy_engine = policy_engine or PolicyEngine(dry_run=dry_run)
        self.verifier = verifier or Verifier(dry_run=dry_run)
        self.evidence_collector = evidence_collector or EvidenceCollector(
            dry_run=dry_run, agent_version=f"vyper-agent/{__version__}"
        )
        self.certificate_builder = certificate_builder or CertificateBuilder()
<<<<<<< HEAD
        self.credential_store = credential_store or AgentCredentialStore()
        self.api_key_required = bool(api_key_required)
        self.expected_api_key = expected_api_key
=======
        resolver = NVMeControllerResolver(
            profiler=self.profiler,
            command_executor=getattr(self.profiler, "command_executor", None),
            sysfs_root=getattr(self.profiler, "sysfs_root", "/sys"),
        )
        self.nvme_scope_resolver = nvme_scope_resolver or resolver.resolve
>>>>>>> f92af61deccff4855c25365623da795ea1595f4a

    def sanitize_device(
        self,
        target: str,
        authorization: Any,
        dry_run: bool | None = None,
        *,
        event_callback: Callable[[JobState], None] | None = None,
        progress_callback: Callable[[Any], None] | None = None,
    ) -> OrchestrationJobResult:
        effective_dry_run = self.dry_run if dry_run is None else bool(dry_run)
        state_history: list[JobState] = _ObservableStateHistory([JobState.PENDING], event_callback)
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        if self._api_key_verification_enabled():
            supplied_key, supplied_device_id = authorization_api_key(authorization)
            if not self._verify_api_key(supplied_key, device_id=supplied_device_id):
                return self._api_key_rejected_result(
                    target=str(target or ""),
                    dry_run=effective_dry_run,
                    state_history=state_history,
                    timestamp=now_iso,
                    reason="Agent API key verification failed.",
                )

        if not target or not str(target).strip():
            execution = SanitizationResult(
                status=SanitizationStatus.FAILED,
                target_device=str(target or ""),
                dry_run=effective_dry_run,
                message="Target device is required.",
                metadata={"method": None, "start_time": now_iso, "end_time": now_iso, "duration_seconds": 0.0},
            )
            verification = self._verification_placeholder(
                target=str(target or ""),
                pathway="",
                status=SanitizationStatus.INCONCLUSIVE,
                verified=False,
                message="Verification skipped because target validation failed.",
            )
            profile = DeviceProfile(device_path=str(target or ""), device_type="UNKNOWN", errors=["Target is missing or empty."])
            policy = PolicyDecision(
                selected_pathway=None,
                device_type="UNKNOWN",
                reason="Target validation failed before profiling.",
                unsupported=True,
            )
            state_history.extend([JobState.PROFILING, JobState.FAILED])
            evidence = self._build_evidence(profile, policy, execution, verification, started_at=now_iso, completed_at=now_iso)
            certificate = self.certificate_builder.build(evidence)
            return OrchestrationJobResult(
                job_state=JobState.FAILED,
                state_history=state_history,
                target=str(target or ""),
                profile=profile,
                policy=policy,
                execution=execution,
                verification=verification,
                evidence=evidence,
                certificate=certificate,
                message="Target validation failed.",
            )

        cleaned_target = str(target).strip()
        state_history.append(JobState.PROFILING)
        started_at = now_iso

        try:
            profile = self.profiler.profile(cleaned_target)
        except Exception as exc:
            execution = SanitizationResult(
                status=SanitizationStatus.FAILED,
                target_device=cleaned_target,
                dry_run=effective_dry_run,
                message=f"Profiling failed: {exc}",
                metadata={"method": None, "start_time": started_at, "end_time": now_iso, "duration_seconds": 0.0},
            )
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway="",
                status=SanitizationStatus.INCONCLUSIVE,
                verified=False,
                message="Verification skipped because profiling failed.",
            )
            policy = PolicyDecision(
                selected_pathway=None,
                device_type="UNKNOWN",
                reason="Profiling failure prevented policy evaluation.",
                unsupported=True,
                warnings=["Policy evaluation skipped due to profiling failure."],
            )
            state_history.append(JobState.FAILED)
            evidence = self._build_evidence(profile=DeviceProfile(device_path=cleaned_target, device_type="UNKNOWN"), policy=policy, execution=execution, verification=verification, started_at=started_at, completed_at=now_iso)
            certificate = self.certificate_builder.build(evidence)
            return OrchestrationJobResult(
                job_state=JobState.FAILED,
                state_history=state_history,
                target=cleaned_target,
                profile=None,
                policy=policy,
                execution=execution,
                verification=verification,
                evidence=evidence,
                certificate=certificate,
                message="Profiling failed.",
            )

        if profile.device_type == "UNKNOWN" or profile.errors:
            status = SanitizationStatus.UNSUPPORTED if profile.device_type == "UNKNOWN" else SanitizationStatus.FAILED
            terminal_state = JobState.UNSUPPORTED if status == SanitizationStatus.UNSUPPORTED else JobState.FAILED
            execution = SanitizationResult(
                status=status,
                target_device=cleaned_target,
                dry_run=effective_dry_run,
                message="Profiling produced insufficient device information for safe sanitization.",
                metadata={"method": None, "start_time": started_at, "end_time": now_iso, "duration_seconds": 0.0},
            )
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway="",
                status=SanitizationStatus.INCONCLUSIVE,
                verified=False,
                message="Verification skipped because profiling data was insufficient.",
            )
            policy = PolicyDecision(
                selected_pathway=None,
                device_type=profile.device_type,
                reason="Insufficient profile data for pathway selection.",
                unsupported=True,
                warnings=list(profile.warnings),
                limitations=["A supported pathway cannot be selected without sufficient profile confidence."],
                metadata={"profile_errors": list(profile.errors)},
            )
            state_history.extend([JobState.POLICY_SELECTED, terminal_state])
            evidence = self._build_evidence(profile, policy, execution, verification, started_at=started_at, completed_at=now_iso)
            certificate = self.certificate_builder.build(evidence)
            return OrchestrationJobResult(
                job_state=terminal_state,
                state_history=state_history,
                target=cleaned_target,
                profile=profile,
                policy=policy,
                execution=execution,
                verification=verification,
                evidence=evidence,
                certificate=certificate,
                message="Insufficient profile information.",
            )

        try:
            policy = self.policy_engine.decide(profile=profile)
        except Exception as exc:
            execution = SanitizationResult(
                status=SanitizationStatus.FAILED,
                target_device=cleaned_target,
                dry_run=effective_dry_run,
                message=f"Policy evaluation failed: {exc}",
                metadata={"method": None, "start_time": started_at, "end_time": now_iso, "duration_seconds": 0.0},
            )
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway="",
                status=SanitizationStatus.INCONCLUSIVE,
                verified=False,
                message="Verification skipped because policy evaluation failed.",
            )
            failed_policy = PolicyDecision(
                selected_pathway=None,
                device_type=profile.device_type,
                reason="Policy engine raised an exception.",
                unsupported=True,
                warnings=["Policy evaluation failed unexpectedly."],
                metadata={"error": str(exc)},
            )
            state_history.extend([JobState.POLICY_SELECTED, JobState.FAILED])
            evidence = self._build_evidence(profile, failed_policy, execution, verification, started_at=started_at, completed_at=now_iso)
            certificate = self.certificate_builder.build(evidence)
            return OrchestrationJobResult(
                job_state=JobState.FAILED,
                state_history=state_history,
                target=cleaned_target,
                profile=profile,
                policy=failed_policy,
                execution=execution,
                verification=verification,
                evidence=evidence,
                certificate=certificate,
                message="Policy evaluation failed.",
            )

        state_history.append(JobState.POLICY_SELECTED)

        if policy.unsupported or not policy.selected_pathway:
            execution = SanitizationResult(
                status=SanitizationStatus.UNSUPPORTED,
                target_device=cleaned_target,
                dry_run=effective_dry_run,
                message=policy.reason or "Policy reported unsupported pathway.",
                metadata={"method": None, "start_time": started_at, "end_time": now_iso, "duration_seconds": 0.0},
            )
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway="",
                status=SanitizationStatus.UNSUPPORTED,
                verified=False,
                message="Verification skipped because policy returned unsupported.",
            )
            state_history.append(JobState.UNSUPPORTED)
            evidence = self._build_evidence(profile, policy, execution, verification, started_at=started_at, completed_at=now_iso)
            certificate = self.certificate_builder.build(evidence)
            return OrchestrationJobResult(
                job_state=JobState.UNSUPPORTED,
                state_history=state_history,
                target=cleaned_target,
                profile=profile,
                policy=policy,
                execution=execution,
                verification=verification,
                evidence=evidence,
                certificate=certificate,
                message=policy.reason or "Unsupported policy decision.",
            )

        pathway_name = str(policy.selected_pathway or "").upper()
        compatibility_issue = self._pathway_compatibility_issue(pathway_name, profile)
        if compatibility_issue:
            if compatibility_issue not in policy.limitations:
                policy.limitations.append(compatibility_issue)
            execution = SanitizationResult(
                status=SanitizationStatus.UNSUPPORTED,
                target_device=cleaned_target,
                dry_run=effective_dry_run,
                message=compatibility_issue,
                metadata={
                    "method": "UNSUPPORTED",
                    "requested_method": pathway_name,
                    "device_type": profile.device_type,
                    "start_time": started_at,
                    "end_time": now_iso,
                    "duration_seconds": 0.0,
                },
            )
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway=pathway_name,
                status=SanitizationStatus.UNSUPPORTED,
                verified=False,
                message="Verification skipped because no compatible implemented pathway is available.",
                limitations=[compatibility_issue],
            )
            state_history.append(JobState.UNSUPPORTED)
            evidence = self._build_evidence(
                profile,
                policy,
                execution,
                verification,
                started_at=started_at,
                completed_at=now_iso,
            )
            certificate = self.certificate_builder.build(evidence)
            return OrchestrationJobResult(
                job_state=JobState.UNSUPPORTED,
                state_history=state_history,
                target=cleaned_target,
                profile=profile,
                policy=policy,
                execution=execution,
                verification=verification,
                evidence=evidence,
                certificate=certificate,
                message=compatibility_issue,
            )

        if progress_callback is None:
            pathway = self._resolve_pathway(pathway_name, effective_dry_run)
        else:
            pathway = self._resolve_pathway(
                pathway_name,
                effective_dry_run,
                progress_callback=progress_callback,
            )
        if pathway is None:
            execution = SanitizationResult(
                status=SanitizationStatus.UNSUPPORTED,
                target_device=cleaned_target,
                dry_run=effective_dry_run,
                message=f"Unknown pathway returned by policy: {pathway_name}",
                metadata={"method": None, "start_time": started_at, "end_time": now_iso, "duration_seconds": 0.0},
            )
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway=pathway_name,
                status=SanitizationStatus.UNSUPPORTED,
                verified=False,
                message="Verification skipped because pathway routing is unsupported.",
            )
            state_history.append(JobState.UNSUPPORTED)
            evidence = self._build_evidence(profile, policy, execution, verification, started_at=started_at, completed_at=now_iso)
            certificate = self.certificate_builder.build(evidence)
            return OrchestrationJobResult(
                job_state=JobState.UNSUPPORTED,
                state_history=state_history,
                target=cleaned_target,
                profile=profile,
                policy=policy,
                execution=execution,
                verification=verification,
                evidence=evidence,
                certificate=certificate,
                message="Unknown policy pathway.",
            )

        authorized, ata_password = self._parse_authorization(authorization)

        if bool(profile.is_system_device) and not effective_dry_run:
            execution = SanitizationResult(
                status=SanitizationStatus.FAILED,
                target_device=cleaned_target,
                dry_run=effective_dry_run,
                message="Target is associated with the running system and was rejected before destructive execution.",
                metadata={"method": pathway_name, "start_time": started_at, "end_time": now_iso, "duration_seconds": 0.0},
            )
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway=pathway_name,
                status=SanitizationStatus.INCONCLUSIVE,
                verified=False,
                message="Verification skipped because the target is system-associated and execution was blocked.",
            )
            state_history.append(JobState.FAILED)
            evidence = self._build_evidence(profile, policy, execution, verification, started_at=started_at, completed_at=now_iso)
            certificate = self.certificate_builder.build(evidence)
            return OrchestrationJobResult(
                job_state=JobState.FAILED,
                state_history=state_history,
                target=cleaned_target,
                profile=profile,
                policy=policy,
                execution=execution,
                verification=verification,
                evidence=evidence,
                certificate=certificate,
                message="System-associated target rejected.",
            )

        if not effective_dry_run and not authorized:
            execution = SanitizationResult(
                status=SanitizationStatus.AWAITING_AUTHORIZATION,
                target_device=cleaned_target,
                dry_run=False,
                message="Explicit authorization is required before destructive execution.",
                metadata={"method": pathway_name, "start_time": started_at, "end_time": now_iso, "duration_seconds": 0.0},
            )
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway=pathway_name,
                status=SanitizationStatus.INCONCLUSIVE,
                verified=False,
                message="Verification deferred while awaiting explicit authorization.",
            )
            state_history.append(JobState.AWAITING_AUTHORIZATION)
            evidence = self._build_evidence(profile, policy, execution, verification, started_at=started_at, completed_at=now_iso)
            certificate = self.certificate_builder.build(evidence)
            return OrchestrationJobResult(
                job_state=JobState.AWAITING_AUTHORIZATION,
                state_history=state_history,
                target=cleaned_target,
                profile=profile,
                policy=policy,
                execution=execution,
                verification=verification,
                evidence=evidence,
                certificate=certificate,
                message="Authorization required.",
            )

        state_history.append(JobState.RUNNING)
        execution = self._run_pathway(
            pathway_name=pathway_name,
            pathway=pathway,
            target=cleaned_target,
            profile=profile,
            authorized=True if effective_dry_run else authorized,
            ata_password=ata_password,
        )

        state_history.append(JobState.VERIFYING)
        if effective_dry_run:
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway=pathway_name,
                status=SanitizationStatus.INCONCLUSIVE,
                verified=False,
                message="Dry-run execution does not provide verification evidence.",
                limitations=["Dry-run mode intentionally avoids destructive operations and verification claims."],
            )
        elif execution.status in {SanitizationStatus.RUNNING, SanitizationStatus.VERIFIED}:
            verification = self.verifier.verify(device=cleaned_target, pathway=pathway_name, profile=profile, sanitization_result=execution)
        else:
            verification = self._verification_placeholder(
                target=cleaned_target,
                pathway=pathway_name,
                status=SanitizationStatus.INCONCLUSIVE,
                verified=False,
                message="Verification skipped because execution did not complete successfully.",
                warnings=["Execution did not reach a verifiable completion state."],
            )

        completed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        evidence = self._build_evidence(profile, policy, execution, verification, started_at=started_at, completed_at=completed_at)
        certificate = self.certificate_builder.build(evidence)

        final_status = evidence.final_status
        if final_status == SanitizationStatus.VERIFIED.value:
            terminal_state = JobState.VERIFIED
        elif final_status == SanitizationStatus.UNSUPPORTED.value:
            terminal_state = JobState.UNSUPPORTED
        elif final_status == SanitizationStatus.INCONCLUSIVE.value:
            terminal_state = JobState.CANCELLED if effective_dry_run else JobState.FAILED
        else:
            terminal_state = JobState.FAILED

        state_history.append(terminal_state)
        return OrchestrationJobResult(
            job_state=terminal_state,
            state_history=state_history,
            target=cleaned_target,
            profile=profile,
            policy=policy,
            execution=execution,
            verification=verification,
            evidence=evidence,
            certificate=certificate,
            message="Workflow completed.",
        )

<<<<<<< HEAD
    def _api_key_verification_enabled(self) -> bool:
        return bool(self.api_key_required or self.expected_api_key)

    def _verify_api_key(self, api_key: str | None, *, device_id: str | None = None) -> bool:
        if not api_key:
            return False
        if self.expected_api_key:
            return hmac.compare_digest(str(api_key), self.expected_api_key)
        return self.credential_store.verify(api_key, device_id=device_id)

    def _api_key_rejected_result(
        self,
        *,
        target: str,
        dry_run: bool,
        state_history: list[JobState],
        timestamp: str,
        reason: str,
    ) -> OrchestrationJobResult:
        execution = SanitizationResult(
            status=SanitizationStatus.FAILED,
            target_device=target,
            dry_run=dry_run,
            message=reason,
            metadata={"method": None, "start_time": timestamp, "end_time": timestamp, "duration_seconds": 0.0},
        )
        verification = self._verification_placeholder(
            target=target,
            pathway="",
            status=SanitizationStatus.INCONCLUSIVE,
            verified=False,
            message="Verification skipped because agent API key validation failed.",
        )
        profile = DeviceProfile(device_path=target, device_type="UNKNOWN", errors=["Agent API key validation failed."])
        policy = PolicyDecision(
            selected_pathway=None,
            device_type="UNKNOWN",
            reason="Agent API key validation failed before profiling.",
            unsupported=True,
        )
        state_history.append(JobState.FAILED)
        evidence = self._build_evidence(profile, policy, execution, verification, started_at=timestamp, completed_at=timestamp)
        certificate = self.certificate_builder.build(evidence)
        return OrchestrationJobResult(
            job_state=JobState.FAILED,
            state_history=state_history,
            target=target,
            profile=profile,
            policy=policy,
            execution=execution,
            verification=verification,
            evidence=evidence,
            certificate=certificate,
            message=reason,
        )

    def _resolve_pathway(self, pathway_name: str, dry_run: bool):
=======
    def _resolve_pathway(self, pathway_name: str, dry_run: bool, *, progress_callback=None):
>>>>>>> f92af61deccff4855c25365623da795ea1595f4a
        if pathway_name == "HDD_OVERWRITE":
            return HDDOverwritePathway(dry_run=dry_run, progress_callback=progress_callback)
        if pathway_name == "ATA_ERASE":
            return ATAErasePathway(dry_run=dry_run)
        if pathway_name in {"CRYPTO_ERASE", "BLOCK_ERASE", "NVME_OVERWRITE"}:
            return NVMeSanitizePathway(dry_run=dry_run)
        return None

    def _pathway_compatibility_issue(self, pathway_name: str, profile: DeviceProfile) -> str | None:
        normalized_device_type = str(profile.device_type or "").strip().upper().replace("_", " ")

        if pathway_name == "HDD_OVERWRITE" and normalized_device_type != "HDD":
            return (
                f"HDD_OVERWRITE is only implemented for HDD devices; "
                f"the profiled device type is {profile.device_type!r}."
            )

        if pathway_name == "ATA_ERASE" and normalized_device_type not in {"HDD", "SATA SSD", "SSD"}:
            return (
                f"ATA_ERASE is only implemented for ATA/SATA HDD or SSD devices; "
                f"the profiled device type is {profile.device_type!r}."
            )

        if pathway_name in {"CRYPTO_ERASE", "BLOCK_ERASE", "NVME_OVERWRITE"} and normalized_device_type != "NVME":
            if pathway_name == "CRYPTO_ERASE" and normalized_device_type in {"SATA SSD", "SSD"}:
                return (
                    "CRYPTO_ERASE was selected for a SATA/ATA SSD, but no implemented "
                    "evidence-backed SATA crypto erase pathway is available. NVMe sanitize "
                    "will not be used, and ATA_ERASE will not be substituted."
                )
            return (
                f"{pathway_name} is only implemented through the NVMe sanitize pathway; "
                f"the profiled device type is {profile.device_type!r}."
            )

        return None

    def _parse_authorization(self, authorization: Any) -> tuple[bool, str | None]:
        if isinstance(authorization, bool):
            return authorization, None
        if isinstance(authorization, dict):
            approved = bool(authorization.get("approved") or authorization.get("authorized") or authorization.get("allow"))
            password = authorization.get("ata_password")
            return approved, str(password) if password else None
        return False, None

    def _run_pathway(
        self,
        *,
        pathway_name: str,
        pathway,
        target: str,
        profile: DeviceProfile,
        authorized: bool,
        ata_password: str | None,
    ) -> SanitizationResult:
        kwargs: dict[str, Any] = {
            "profile": profile,
            "authorized": authorized,
            "system_associated": bool(profile.is_system_device),
        }
        if pathway_name in {"CRYPTO_ERASE", "BLOCK_ERASE", "NVME_OVERWRITE"}:
            kwargs["selected_method"] = pathway_name
            try:
                kwargs["controller_scope"] = self.nvme_scope_resolver(target)
            except Exception as exc:
                kwargs["controller_scope"] = {
                    "scope_proven": False,
                    "execution_eligible": False,
                    "execution_blockers": [f"NVMe controller resolution failed safely: {type(exc).__name__}"],
                }
        if pathway_name == "ATA_ERASE" and ata_password:
            kwargs["password"] = ata_password
        return pathway.execute(target, **kwargs)

    def _verification_placeholder(
        self,
        *,
        target: str,
        pathway: str,
        status: SanitizationStatus,
        verified: bool,
        message: str,
        warnings: list[str] | None = None,
        limitations: list[str] | None = None,
    ) -> VerificationResult:
        return VerificationResult(
            status=status,
            device=target,
            pathway=pathway,
            verified=verified,
            message=message,
            evidence={"source": "orchestrator", "status": _status_to_text(status)},
            warnings=list(warnings or []),
            errors=[],
            limitations=list(limitations or []),
        )

    def _build_evidence(
        self,
        profile: DeviceProfile,
        policy: PolicyDecision,
        execution: SanitizationResult,
        verification: VerificationResult,
        *,
        started_at: str,
        completed_at: str,
    ) -> EvidenceRecord:
        return self.evidence_collector.create_record(
            device_profile=profile,
            policy_decision=policy,
            execution_result=execution,
            verification_result=verification,
            started_at=started_at,
            completed_at=completed_at,
        )


def _status_to_text(status: SanitizationStatus) -> str:
    return status.value if isinstance(status, SanitizationStatus) else str(status)


def _result_to_summary(result: OrchestrationJobResult) -> dict[str, Any]:
    return {
        "job_state": result.job_state.value,
        "state_history": [state.value for state in result.state_history],
        "target": result.target,
        "profile": {
            "device_path": result.profile.device_path if result.profile else None,
            "device_type": result.profile.device_type if result.profile else None,
            "model": result.profile.model if result.profile else None,
            "serial_number": result.profile.serial_number if result.profile else None,
        }
        if result.profile
        else None,
        "policy": {
            "selected_pathway": result.policy.selected_pathway if result.policy else None,
            "reason": result.policy.reason if result.policy else None,
            "unsupported": result.policy.unsupported if result.policy else None,
        }
        if result.policy
        else None,
        "execution": {
            "status": result.execution.status.value if result.execution else None,
            "message": result.execution.message if result.execution else None,
            "dry_run": result.execution.dry_run if result.execution else None,
        }
        if result.execution
        else None,
        "verification": {
            "status": result.verification.status.value if result.verification else None,
            "verified": result.verification.verified if result.verification else None,
            "message": result.verification.message if result.verification else None,
        }
        if result.verification
        else None,
        "evidence": {
            "job_id": result.evidence.job_id if result.evidence else None,
            "final_status": result.evidence.final_status if result.evidence else None,
        }
        if result.evidence
        else None,
        "certificate": {
            "certificate_id": result.certificate.certificate_id if result.certificate else None,
            "outcome_kind": result.certificate.outcome_kind if result.certificate else None,
            "successful_sanitization_claim": result.certificate.successful_sanitization_claim if result.certificate else None,
        }
        if result.certificate
        else None,
        "message": result.message,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VYPER device sanitization orchestrator")
    parser.add_argument("device", help="Target block device path")
    parser.add_argument("--dry-run", action="store_true", help="Run with dry-run safeguards enabled")
    parser.add_argument("--authorize", action="store_true", help="Explicitly authorize destructive execution")
    parser.add_argument("--ata-password", default=None, help="ATA password when required by ATA secure erase")
    parser.add_argument("--api-key", default=None, help="Agent API key to authenticate this request")
    parser.add_argument("--require-api-key", action="store_true", help="Require the supplied API key to match the generated device credential")
    args = parser.parse_args(argv)

    authorization = {"approved": bool(args.authorize)}
    if args.ata_password:
        authorization["ata_password"] = args.ata_password
    if args.api_key:
        authorization["agent_api_key"] = args.api_key

    agent = VYPERAgent(dry_run=bool(args.dry_run), api_key_required=bool(args.require_api_key))
    result = agent.sanitize_device(args.device, authorization, dry_run=bool(args.dry_run))

    summary = _result_to_summary(result)
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
