from __future__ import annotations

from agent.credentials import AgentCredentialStore


def test_generates_device_scoped_api_key(tmp_path):
    store = AgentCredentialStore(root=tmp_path)

    first = store.generate()
    second = store.generate()

    assert first.device_id == second.device_id
    assert first.api_key.startswith("vyp_")
    assert second.api_key.startswith("vyp_")
    assert first.api_key != second.api_key
    assert store.verify(second.api_key, device_id=second.device_id)
    assert not store.verify(second.api_key, device_id="another-device")


def test_migrates_legacy_agent_key_file(tmp_path):
    legacy_key = "vyp_legacy-key"
    legacy_file = tmp_path / "agent_api_key"
    legacy_file.write_text(legacy_key + "\n", encoding="utf-8")

    store = AgentCredentialStore(root=tmp_path)
    credentials = store.load()

    assert credentials is not None
    assert credentials.api_key == legacy_key
    assert credentials.device_id
    assert (tmp_path / "agent_credentials.json").exists()
