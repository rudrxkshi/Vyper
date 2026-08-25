from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from vyper_version import __version__


FORBIDDEN_PARTS = {".git", ".venv", "node_modules", "__pycache__", ".pytest_cache"}
FORBIDDEN_SUFFIXES = (".pyc", ".db", ".env", ".env.local", ".map")
REQUIRED_SUFFIXES = (
	"/install.sh", "/uninstall.sh", "/manifest.json", "/checksums.txt",
	"/payload/config.toml", "/payload/systemd/vyper-agent.service",
	"/payload/systemd/vyper-executor.service", "/payload/trust/trusted-release-keys.json", "/payload/sbom.cdx.json",
	"/payload/systemd/vyper-console.service", "/payload/boot/build_boot_image.py",
	"/payload/boot/initramfs-tools/hooks/vyper",
	"/payload/boot/initramfs-tools/scripts/local-premount/vyper",
	"/payload/docs/KNOWN_LIMITATIONS.md", "/payload/docs/RELEASE_CANDIDATE_REPORT.md",
	"/payload/ui/index.html",
)


def validate_release(release_directory: str | Path) -> dict[str, object]:
	release = Path(release_directory)
	manifest = json.loads((release / "manifest.json").read_text(encoding="utf-8"))
	artifact = release / str(manifest["filename"])
	digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
	if manifest.get("version") != __version__:
		raise ValueError("Release manifest version does not match runtime version.")
	if digest != manifest.get("sha256") or artifact.stat().st_size != manifest.get("size_bytes"):
		raise ValueError("Release archive checksum or size does not match its manifest.")
	sbom = release / str((manifest.get("sbom") or {}).get("filename") or "")
	if not sbom.is_file() or hashlib.sha256(sbom.read_bytes()).hexdigest() != (manifest.get("sbom") or {}).get("sha256"):
		raise ValueError("Release SBOM is missing or does not match its manifest reference.")
	with tarfile.open(artifact, "r:gz") as archive:
		members = archive.getmembers()
		names = [member.name for member in members]
		for suffix in REQUIRED_SUFFIXES:
			if not any(name.endswith(suffix) for name in names):
				raise ValueError(f"Release archive is missing required content: {suffix}")
		for member in members:
			parts = set(Path(member.name).parts)
			if parts & FORBIDDEN_PARTS or member.name.endswith(FORBIDDEN_SUFFIXES):
				raise ValueError(f"Release archive contains forbidden content: {member.name}")
			if member.isfile() and member.size <= 2 * 1024 * 1024:
				content = archive.extractfile(member).read().lower()
				if any(marker in content for marker in (b"begin private key", b"ata_password=", b"agent_token=")):
					raise ValueError(f"Release archive contains a secret marker: {member.name}")
	return {"valid": True, "version": manifest["version"], "sha256": digest,
		"size_bytes": artifact.stat().st_size, "files_checked": len(members)}


def main() -> None:
	parser = argparse.ArgumentParser(description="Validate a VYPER Linux release candidate")
	parser.add_argument("--release-directory", type=Path, default=ROOT / "release")
	args = parser.parse_args()
	print(json.dumps(validate_release(args.release_directory), indent=2, sort_keys=True))


if __name__ == "__main__":
	main()
