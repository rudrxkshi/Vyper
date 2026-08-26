from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from agent.command_runner import CommandExecutor, SubprocessCommandExecutor


def secure_boot_status(*, command_executor: CommandExecutor | None = None,
	signing_certificate: str | Path | None = None) -> dict[str, Any]:
	executor = command_executor or SubprocessCommandExecutor()
	try:
		state = executor.run(["mokutil", "--sb-state"], timeout=10)
	except (OSError, FileNotFoundError):
		return {"status": "UNKNOWN", "secure_boot_enabled": None, "reason": "mokutil is unavailable.", "read_only": True}
	text = f"{state.stdout}\n{state.stderr}".lower()
	if not state.success or state.exit_code != 0:
		return {"status": "UNKNOWN", "secure_boot_enabled": None, "reason": "Secure Boot state could not be read.", "read_only": True}
	if "disabled" in text:
		return {"status": "UNSUPPORTED", "secure_boot_enabled": False,
			"reason": "Secure Boot is disabled; VYPER did not change firmware state.", "read_only": True}
	if "enabled" not in text:
		return {"status": "UNKNOWN", "secure_boot_enabled": None, "reason": "Secure Boot state was not recognized.", "read_only": True}
	certificate = Path(signing_certificate or os.getenv("VYPER_SECURE_BOOT_CERTIFICATE", ""))
	if not str(certificate) or not certificate.is_file():
		return {"status": "REQUIRES_KEY_ENROLLMENT", "secure_boot_enabled": True,
			"reason": "A VYPER kernel/UKI signing certificate is not configured.", "read_only": True}
	try:
		enrolled = executor.run(["mokutil", "--test-key", str(certificate)], timeout=10)
	except (OSError, FileNotFoundError):
		enrolled = None
	if enrolled is None or not enrolled.success or enrolled.exit_code != 0:
		return {"status": "REQUIRES_KEY_ENROLLMENT", "secure_boot_enabled": True,
			"certificate": str(certificate), "reason": "The configured signing certificate is not enrolled through shim/MOK.", "read_only": True}
	return {"status": "SUPPORTED", "secure_boot_enabled": True, "certificate": str(certificate),
		"reason": "Secure Boot is enabled and the configured VYPER signing certificate is enrolled.", "read_only": True}
