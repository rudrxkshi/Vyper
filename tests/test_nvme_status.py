from __future__ import annotations

import json

from agent.nvme_status import parse_sanitize_log, sanitize_log_command


def test_sanitize_log_command_uses_json_output():
    assert sanitize_log_command("/dev/nvme0n1") == ["nvme", "sanitize-log", "/dev/nvme0n1", "--output-format=json"]


def test_parse_sanitize_log_completed_with_global_data_erased_bit():
    payload = json.dumps({"nvme0n1": {"sstat": {"status": "0x101 Completed Successfully"}}})

    parsed = parse_sanitize_log(payload)

    assert parsed is not None
    assert parsed["status"] == "COMPLETED"
    assert parsed["sstat"] == 0x101
    assert parsed["status_code"] == 1
    assert parsed["global_data_erased"] is True


def test_parse_sanitize_log_aborted_from_failed_status_text():
    payload = json.dumps({"nvme0n1": {"sstat": {"status": "(3) Aborted by user"}}})

    parsed = parse_sanitize_log(payload)

    assert parsed is not None
    assert parsed["status"] == "ABORTED"
    assert parsed["status_code"] == 3


def test_parse_sanitize_log_rejects_unsupported_status_bits():
    payload = json.dumps({"nvme0n1": {"sstat": {"status": "0x208"}}})

    assert parse_sanitize_log(payload) is None


def test_parse_sanitize_log_rejects_boolean_status():
    payload = json.dumps({"nvme0n1": {"sstat": {"status": True}}})

    assert parse_sanitize_log(payload) is None
