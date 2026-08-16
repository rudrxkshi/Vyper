from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Sequence


@dataclass(slots=True)
class CommandResult:
    command: Sequence[str] | str
    success: bool
    exit_code: int | None
    stdout: str = ""
    stderr: str = ""
    dry_run: bool = False
    metadata: dict[str, object] = field(default_factory=dict)


class CommandExecutor(ABC):
    @abstractmethod
    def run(
        self,
        command: Sequence[str] | str,
        timeout: float | None = None,
        cwd: str | None = None,
    ) -> CommandResult:
        """Execute a command and return a structured result."""


class DryRunCommandExecutor(CommandExecutor):
    def run(
        self,
        command: Sequence[str] | str,
        timeout: float | None = None,
        cwd: str | None = None,
    ) -> CommandResult:
        return CommandResult(
            command=command,
            success=True,
            exit_code=0,
            stdout="",
            stderr="",
            dry_run=True,
            metadata={"mode": "dry-run", "cwd": cwd, "timeout": timeout},
        )


class SubprocessCommandExecutor(CommandExecutor):
    def run(
        self,
        command: Sequence[str] | str,
        timeout: float | None = None,
        cwd: str | None = None,
    ) -> CommandResult:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            check=False,
        )
        stdout = completed.stdout or ""
        stderr = completed.stderr or ""
        return CommandResult(
            command=command,
            success=completed.returncode == 0,
            exit_code=completed.returncode,
            stdout=stdout,
            stderr=stderr,
            dry_run=False,
            metadata={"cwd": cwd, "timeout": timeout},
        )
