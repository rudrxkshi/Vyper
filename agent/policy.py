from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent.profiler import DeviceProfile


@dataclass(slots=True)
class PolicyDecision:
    selected_pathway: str | None = None
    device_type: str = "UNKNOWN"
    reason: str = ""
    supported_methods: list[str] = field(default_factory=list)
    policy: str = "default"
    requires_authorization: bool = True
    unsupported: bool = False
    warnings: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    policy_name: str | None = None
    rationale: str = ""

    def __post_init__(self) -> None:
        if self.selected_pathway is None and self.policy_name is not None:
            self.selected_pathway = self.policy_name
        if not self.reason and self.rationale:
            self.reason = self.rationale
        if self.policy_name is None and self.selected_pathway is not None:
            self.policy_name = self.selected_pathway
        if not self.rationale and self.reason:
            self.rationale = self.reason


class PolicyEngine:
    def __init__(self, *, dry_run: bool = True, policy: str = "default") -> None:
        self.dry_run = dry_run
        self.policy = policy

    def decide(
        self,
        profile: DeviceProfile | None = None,
        *,
        device_type: str | None = None,
        capabilities: dict[str, Any] | None = None,
    ) -> PolicyDecision:
        if profile is not None:
            device_type = profile.device_type
            capabilities = profile.capabilities if capabilities is None else capabilities

        if device_type is None:
            device_type = "UNKNOWN"

        normalized_type = str(device_type).strip().upper()
        caps = dict(capabilities or {})

        if normalized_type == "HDD":
            return self._decide_hdd(caps)
        if normalized_type in {"SATA SSD", "SATA_SSD", "SSD"}:
            return self._decide_sata_ssd(caps)
        if normalized_type == "NVME":
            return self._decide_nvme(caps)

        return PolicyDecision(
            selected_pathway=None,
            device_type=normalized_type or "UNKNOWN",
            reason="Unknown device type; unsupported for sanitization policy selection.",
            supported_methods=[],
            policy=self.policy,
            requires_authorization=True,
            unsupported=True,
            warnings=["Device type is unknown or unsupported; no sanitization pathway may be selected safely."],
            limitations=["Policy requires a recognized HDD, SATA SSD, or NVMe device type."],
            metadata={"device_type": normalized_type, "capabilities": caps},
        )

    def _decide_hdd(self, capabilities: dict[str, Any]) -> PolicyDecision:
        security = capabilities.get("security") or {}
        ata_supported = bool(security.get("supported"))
        ata_frozen = bool(security.get("frozen"))
        explicit_ata = self.policy.upper() == "ATA_ERASE"

        supported_methods = ["HDD_OVERWRITE"]
        if ata_supported:
            supported_methods.append("ATA_ERASE")

        if explicit_ata and ata_supported and not ata_frozen:
            return PolicyDecision(
                selected_pathway="ATA_ERASE",
                device_type="HDD",
                reason="HDD has ATA security capability and ATA erase is explicitly selected and not frozen.",
                supported_methods=["HDD_OVERWRITE", "ATA_ERASE"],
                policy=self.policy,
                requires_authorization=True,
                unsupported=False,
                warnings=[],
                limitations=["ATA erase is only selected when capability is exposed and the device is not frozen."],
                metadata={"capabilities": capabilities},
            )

        if explicit_ata and ata_supported and ata_frozen:
            return PolicyDecision(
                selected_pathway=None,
                device_type="HDD",
                reason="ATA erase was requested but the device is frozen; requires manual handling.",
                supported_methods=["HDD_OVERWRITE", "ATA_ERASE"],
                policy=self.policy,
                requires_authorization=True,
                unsupported=True,
                warnings=["ATA security is present but the device is frozen."],
                limitations=["ATA erase is unavailable while the security state is frozen."],
                metadata={"capabilities": capabilities},
            )

        return PolicyDecision(
            selected_pathway="HDD_OVERWRITE",
            device_type="HDD",
            reason="Default HDD policy selects host-level overwrite unless ATA erase is explicitly enabled and available.",
            supported_methods=["HDD_OVERWRITE"],
            policy=self.policy,
            requires_authorization=True,
            unsupported=False,
            warnings=[],
            limitations=["This is the default HDD pathway; ATA erase remains optional and must be explicitly selected."],
            metadata={"capabilities": capabilities},
        )

    def _decide_sata_ssd(self, capabilities: dict[str, Any]) -> PolicyDecision:
        crypto_supported = self._read_bool(capabilities, ["crypto_erase_supported", "crypto_supported", "sanicap.crypto_erase"], default=False)
        crypto_applicable = self._read_bool(capabilities, ["crypto_erase_applicable", "crypto_applicable"], default=False)
        secure_erase_supported = self._read_bool(capabilities, ["secure_erase_supported", "secure_erase", "security.secure_erase_supported"], default=False)
        ata_supported = self._read_bool(capabilities, ["ata_erase_supported", "security.supported"], default=False)

        supported_methods: list[str] = []
        if crypto_supported:
            supported_methods.append("CRYPTO_ERASE")
        if secure_erase_supported or ata_supported:
            supported_methods.append("ATA_ERASE")

        if crypto_supported and crypto_applicable:
            return PolicyDecision(
                selected_pathway="CRYPTO_ERASE",
                device_type="SATA SSD",
                reason="SATA SSD supports cryptographic erase and the device policy permits it.",
                supported_methods=supported_methods,
                policy=self.policy,
                requires_authorization=True,
                unsupported=False,
                warnings=[],
                limitations=["Crypto erase is preferred only when supported and applicable; applicability must be established from device/security metadata."],
                metadata={"capabilities": capabilities},
            )

        if secure_erase_supported or ata_supported:
            return PolicyDecision(
                selected_pathway="ATA_ERASE",
                device_type="SATA SSD",
                reason="SATA SSD does not support applicable crypto erase, but a supported device-level sanitization method is available.",
                supported_methods=supported_methods,
                policy=self.policy,
                requires_authorization=True,
                unsupported=False,
                warnings=["Ordinary host-level overwrite is not selected for SATA SSDs."],
                limitations=["A non-crypto device-supported method was selected only because no applicable crypto erase could be established."],
                metadata={"capabilities": capabilities},
            )

        return PolicyDecision(
            selected_pathway=None,
            device_type="SATA SSD",
            reason="No acceptable device-supported sanitization method is available; requires manual handling.",
            supported_methods=[],
            policy=self.policy,
            requires_authorization=True,
            unsupported=True,
            warnings=["SATA SSD has no supported applicable cryptographic or device-level sanitization method in the current metadata."],
            limitations=["Generic host overwriting is not permitted for SATA SSDs by the VYPER architecture."],
            metadata={"capabilities": capabilities},
        )

    def _decide_nvme(self, capabilities: dict[str, Any]) -> PolicyDecision:
        sanicap = capabilities.get("sanicap") or {}

        crypto_supported = bool(self._read_bool(capabilities, ["crypto_erase_supported", "crypto_supported"], default=False) or bool(sanicap.get("crypto_erase")))
        block_supported = bool(self._read_bool(capabilities, ["block_erase_supported"], default=False) or bool(sanicap.get("block_erase")))
        overwrite_supported = bool(self._read_bool(capabilities, ["overwrite_supported"], default=False) or bool(sanicap.get("overwrite")))
        crypto_applicable = self._read_bool(capabilities, ["crypto_erase_applicable", "crypto_applicable"], default=False)

        supported_methods: list[str] = []
        if crypto_supported:
            supported_methods.append("CRYPTO_ERASE")
        if block_supported:
            supported_methods.append("BLOCK_ERASE")
        if overwrite_supported:
            supported_methods.append("NVME_OVERWRITE")

        if not supported_methods:
            return PolicyDecision(
                selected_pathway=None,
                device_type="NVMe",
                reason="NVMe device exposes no acceptable sanitization capability in the current metadata; requires manual handling.",
                supported_methods=[],
                policy=self.policy,
                requires_authorization=True,
                unsupported=True,
                warnings=["No supported NVMe sanitization capability is available from the current profile metadata."],
                limitations=["Ordinary host overwrite is not considered an acceptable NVMe fallback by this architecture."],
                metadata={"capabilities": capabilities},
            )

        if crypto_supported and crypto_applicable:
            return PolicyDecision(
                selected_pathway="CRYPTO_ERASE",
                device_type="NVMe",
                reason="NVMe device supports cryptographic erase and the current policy establishes that it is applicable.",
                supported_methods=supported_methods,
                policy=self.policy,
                requires_authorization=True,
                unsupported=False,
                warnings=[],
                limitations=["Crypto erase is preferred only when supported and applicable; the policy must not assume applicability without evidence."],
                metadata={"capabilities": capabilities},
            )

        if block_supported:
            return PolicyDecision(
                selected_pathway="BLOCK_ERASE",
                device_type="NVMe",
                reason="NVMe device does not have applicable crypto erase, but a supported device-level sanitization mechanism is available.",
                supported_methods=supported_methods,
                policy=self.policy,
                requires_authorization=True,
                unsupported=False,
                warnings=["Crypto erase was not selected because it is unsupported or not applicable in the current metadata."],
                limitations=["The device-level sanitization mechanism must be verified by the pathway and verifier stage."],
                metadata={"capabilities": capabilities},
            )

        if overwrite_supported:
            return PolicyDecision(
                selected_pathway="NVME_OVERWRITE",
                device_type="NVMe",
                reason="No crypto or block erase is available, but the NVMe device reports a supported overwrite capability.",
                supported_methods=supported_methods,
                policy=self.policy,
                requires_authorization=True,
                unsupported=False,
                warnings=["Device-supported overwrite is used only when it is the accepted NVMe mechanism and is not a generic host-level fallback."],
                limitations=["This pathway still requires method-specific verification and should not be treated as equivalent to ordinary host overwrite."],
                metadata={"capabilities": capabilities},
            )

        return PolicyDecision(
            selected_pathway=None,
            device_type="NVMe",
            reason="No acceptable NVMe sanitization mechanism is available from the current profile; requires manual handling.",
            supported_methods=[],
            policy=self.policy,
            requires_authorization=True,
            unsupported=True,
            warnings=["Capability information is insufficient or not applicable for a safe NVMe policy decision."],
            limitations=["A generic host-level overwrite fallback is not allowed for NVMe under the VYPER architecture."],
            metadata={"capabilities": capabilities},
        )

    def _read_bool(self, capabilities: dict[str, Any], keys: list[str], *, default: bool = False) -> bool:
        for key in keys:
            value = capabilities
            for part in key.split("."):
                if not isinstance(value, dict):
                    value = None
                    break
                value = value.get(part)
            if value is None:
                continue
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                lowered = value.strip().lower()
                if lowered in {"true", "yes", "1", "supported", "applicable"}:
                    return True
                if lowered in {"false", "no", "0", "unsupported", "not_applicable"}:
                    return False
            if isinstance(value, (int, float)):
                return bool(value)
        return default
