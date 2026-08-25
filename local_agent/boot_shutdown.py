from __future__ import annotations

import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


def _now() -> str:
	return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class BootShutdownCoordinator:
	"""Bounded, init-system-aware poweroff for the temporary boot environment."""

	def __init__(self, *, runner: Callable[..., Any] = subprocess.run,
		which: Callable[[str], str | None] = shutil.which,
		pid1_comm_path: str | Path = "/proc/1/comm", command_timeout: float = 10.0,
		completion_timeout: float = 5.0, wait: Callable[[float], None] = time.sleep) -> None:
		self.runner = runner
		self.which = which
		self.pid1_comm_path = Path(pid1_comm_path)
		self.command_timeout = command_timeout
		self.completion_timeout = completion_timeout
		self.wait = wait

	def attempt(self, *, durability: Callable[[], dict[str, Any]],
		record: Callable[[dict[str, Any]], None],
		recover_durability: Callable[[], None] | None = None) -> dict[str, Any]:
		requested_at = _now()
		commands = self._commands()
		first_method, first_command = commands[0] if commands else (None, None)
		base = {"shutdown_requested_at": requested_at, "shutdown_status": "REQUESTED",
			"shutdown_method": first_method,
			"shutdown_command_result": {"state": "PENDING", "command": first_command},
			"shutdown_fallback_used": False, "durability": None}
		record(dict(base))
		durability_result = durability()
		base["durability"] = durability_result
		attempts = []
		for index, (method, command) in enumerate(commands):
			if index:
				if recover_durability is not None:
					recover_durability()
				record({**base, "shutdown_method": method,
					"shutdown_command_result": {"state": "PENDING", "command": command},
					"shutdown_fallback_used": True})
				durability_result = durability()
				base["durability"] = durability_result
			entry = {"method": method, "command": command, "returncode": None,
				"timed_out": False, "error": None}
			try:
				completed = self.runner(command, check=False, timeout=self.command_timeout,
					capture_output=True, text=True)
				entry["returncode"] = completed.returncode
			except subprocess.TimeoutExpired:
				entry["timed_out"] = True
			except OSError as exc:
				entry["error"] = type(exc).__name__
			attempts.append(entry)
			if entry["returncode"] == 0:
				self.wait(self.completion_timeout)
		result = {**base, "shutdown_status": "FAILED",
			"shutdown_method": attempts[-1]["method"] if attempts else None,
			"shutdown_command_result": attempts,
			"shutdown_fallback_used": len(attempts) > 1,
			"shutdown_warning": "Poweroff commands returned or failed; sanitization outcome is unchanged."}
		if recover_durability is not None:
			recover_durability()
		record(result)
		return result

	def _commands(self) -> list[tuple[str, list[str]]]:
		commands: list[tuple[str, list[str]]] = []
		if self._pid1() == "systemd" and self.which("systemctl"):
			commands.append(("systemctl", [self.which("systemctl") or "systemctl", "poweroff"]))
		for method, name, args in (
			("poweroff", "poweroff", ["-f"]),
			("shutdown", "shutdown", ["-h", "now"]),
			("reboot-poweroff", "reboot", ["-p"]),
		):
			path = self.which(name)
			if path:
				commands.append((method, [path, *args]))
		busybox = self.which("busybox")
		if busybox:
			commands.append(("busybox-poweroff", [busybox, "poweroff", "-f"]))
		return commands

	def _pid1(self) -> str:
		try:
			return self.pid1_comm_path.read_text(encoding="utf-8", errors="replace").strip()
		except OSError:
			return ""
