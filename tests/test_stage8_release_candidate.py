from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path

from backend.app.schemas import AgentJobEventUpload, CentralJobCreate, SanitizeJobCreate
from local_agent.schemas import SanitizeJobRequest
from vyper_version import __version__


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = json.loads((ROOT / "tests/fixtures/stage8_api_contract.json").read_text(encoding="utf-8"))


def test_shared_golden_contract_validates_against_backend_and_local_models():
	local = CONTRACT["local_sanitize_request"]
	assert SanitizeJobCreate.model_validate(local).model_dump() == local
	assert SanitizeJobRequest.model_validate(local).model_dump() == local
	central = CentralJobCreate.model_validate(CONTRACT["central_job_create"])
	assert central.execution_mode == "boot_sanitize"
	event = AgentJobEventUpload.model_validate(CONTRACT["boot_lifecycle_event"])
	assert event.agent_protocol_version == "1" and event.sequence == 3
	assert CONTRACT["versions"] == {"product": __version__, "local_api": "2", "agent_protocol": "1"}


def test_release_archive_contains_rc_boot_tools_docs_and_no_forbidden_files():
	manifest = json.loads((ROOT / "release/manifest.json").read_text(encoding="utf-8"))
	artifact = ROOT / "release" / manifest["filename"]
	assert manifest["version"] == __version__
	assert hashlib.sha256(artifact.read_bytes()).hexdigest() == manifest["sha256"]
	with tarfile.open(artifact, "r:gz") as archive:
		names = archive.getnames()
	for suffix in (
		"/payload/boot/build_boot_image.py", "/payload/boot/initramfs-tools/hooks/vyper",
		"/payload/docs/KNOWN_LIMITATIONS.md", "/payload/docs/RELEASE_CANDIDATE_REPORT.md",
		"/payload/docs/DEMO_SCRIPT.md", "/payload/ui/index.html",
	):
		assert any(name.endswith(suffix) for name in names), suffix
	for name in names:
		parts = set(Path(name).parts)
		assert not parts.intersection({".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"})
		assert not name.endswith((".pyc", ".db", ".env", ".env.local"))
