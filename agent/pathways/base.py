from __future__ import annotations

from abc import ABC, abstractmethod

from agent.common import SanitizationResult, SanitizationStatus


class SanitizationPathway(ABC):
    """Base class for all sanitization pathways.

    Concrete implementations are expected to encapsulate the execution logic for a
    specific device sanitization mechanism while keeping the result contract
    consistent across the whole application.
    """

    def __init__(self, *, dry_run: bool = True, command_executor=None) -> None:
        self.dry_run = dry_run
        self.command_executor = command_executor

    @abstractmethod
    def execute(self, target: str) -> SanitizationResult:
        """Run the sanitization pathway against a device target."""

    def _unsupported_result(self, target: str, reason: str) -> SanitizationResult:
        return SanitizationResult(
            status=SanitizationStatus.UNSUPPORTED,
            target_device=target,
            dry_run=self.dry_run,
            message=reason,
        )

    def _failed_result(self, target: str, reason: str) -> SanitizationResult:
        return SanitizationResult(
            status=SanitizationStatus.FAILED,
            target_device=target,
            dry_run=self.dry_run,
            message=reason,
        )
