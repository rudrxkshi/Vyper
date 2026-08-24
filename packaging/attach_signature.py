from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path


SUPPORTED_TYPES = {"minisign", "cosign", "gpg"}


def attach_signature(artifact: Path, signature: Path, signature_type: str, manifest_path: Path | None = None) -> Path:
	artifact = artifact.resolve()
	signature = signature.resolve()
	manifest_path = (manifest_path or artifact.with_name("manifest.json")).resolve()
	if signature_type not in SUPPORTED_TYPES:
		raise ValueError(f"Unsupported signature type: {signature_type}")
	manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
	if manifest.get("filename") != artifact.name or not artifact.is_file() or not signature.is_file():
		raise ValueError("Artifact, signature, and manifest do not describe the same release.")
	destination = artifact.with_name(f"{artifact.name}.{signature_type}.sig")
	shutil.copy2(signature, destination)
	manifest["signature_status"] = "signed"
	manifest["signature_type"] = signature_type
	manifest["signature_file"] = destination.name
	manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
	return destination


def main() -> None:
	parser = argparse.ArgumentParser(description="Attach a detached signature created by an external signing service")
	parser.add_argument("artifact", type=Path)
	parser.add_argument("signature", type=Path)
	parser.add_argument("--type", required=True, choices=sorted(SUPPORTED_TYPES))
	parser.add_argument("--manifest", type=Path)
	args = parser.parse_args()
	print(attach_signature(args.artifact, args.signature, args.type, args.manifest))


if __name__ == "__main__":
	main()
