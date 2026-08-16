from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class SanitizationStatus(str, Enum):
    PENDING = "PENDING"
    PROFILING = "PROFILING"
    POLICY_SELECTED = "POLICY_SELECTED"
    AWAITING_AUTHORIZATION = "AWAITING_AUTHORIZATION"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"
    CANCELLED = "CANCELLED"


class JobState(str, Enum):
    PENDING = "PENDING"
    PROFILING = "PROFILING"
    POLICY_SELECTED = "POLICY_SELECTED"
    AWAITING_AUTHORIZATION = "AWAITING_AUTHORIZATION"
    RUNNING = "RUNNING"
    VERIFYING = "VERIFYING"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    INCONCLUSIVE = "INCONCLUSIVE"
    UNSUPPORTED = "UNSUPPORTED"
    CANCELLED = "CANCELLED"


@dataclass(slots=True)
class ErrorRecord:
    code: str
    message: str
    details: str | None = None


@dataclass(slots=True)
class WarningRecord:
    code: str
    message: str
    details: str | None = None


@dataclass(slots=True)
class SanitizationResult:
    status: SanitizationStatus
    target_device: str
    dry_run: bool = False
    message: str = ""
    errors: list[ErrorRecord] = field(default_factory=list)
    warnings: list[WarningRecord] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_error(self, code: str, message: str, details: str | None = None) -> None:
        self.errors.append(ErrorRecord(code=code, message=message, details=details))

    def add_warning(self, code: str, message: str, details: str | None = None) -> None:
        self.warnings.append(WarningRecord(code=code, message=message, details=details))

    def is_successful(self) -> bool:
        return self.status == SanitizationStatus.VERIFIED
