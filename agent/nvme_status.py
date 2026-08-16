from __future__ import annotations

import json
import re
from typing import Any


def sanitize_log_command(target: str) -> list[str]:
    return ["nvme", "sanitize-log", target, "--output-format=json"]


def parse_sanitize_log(output: str) -> dict[str, Any] | None:
    """Parse the documented nvme-cli JSON sanitize-log SSTAT field conservatively."""
    normalized = str(output or "").strip()
    if not normalized:
        return None
    try:
        payload = json.loads(normalized)
    except (TypeError, ValueError):
        return None

    sstat = _find_sstat(payload)
    if sstat is None:
        return None
    raw_value, status_text = _extract_status_value(sstat)
    if raw_value is None or raw_value < 0 or raw_value & ~0x107:
        return None

    status_code = raw_value & 0x7
    status = {1: "COMPLETED", 2: "IN_PROGRESS", 3: "FAILED"}.get(status_code, "INVALID")
    if status == "FAILED" and "abort" in status_text.lower():
        status = "ABORTED"
    return {
        "status": status,
        "sstat": raw_value,
        "status_code": status_code,
        "global_data_erased": bool(raw_value & 0x100),
    }


def _find_sstat(value: Any) -> Any | None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).strip().lower() == "sstat":
                return nested
        for nested in value.values():
            found = _find_sstat(nested)
            if found is not None:
                return found
    elif isinstance(value, list):
        for nested in value:
            found = _find_sstat(nested)
            if found is not None:
                return found
    return None


def _extract_status_value(sstat: Any) -> tuple[int | None, str]:
    status = sstat.get("status") if isinstance(sstat, dict) else sstat
    if isinstance(status, bool):
        return None, ""
    if isinstance(status, int):
        return status, str(status)
    if not isinstance(status, str):
        return None, ""
    match = re.match(r"^\s*\(?\s*(0[xX][0-9a-fA-F]+|\d+)\s*\)?", status)
    if match is None:
        return None, status
    try:
        return int(match.group(1), 0), status
    except ValueError:
        return None, status
