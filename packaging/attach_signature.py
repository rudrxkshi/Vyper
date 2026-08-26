from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


from local_agent.release_signing import public_key_id, signature_bytes, verify_detached

SUPPORTED_TYPES = {"ed25519"}


def attach_signature(artifact: Path, signature: Path, signature_type: str, manifest_path: Path | None = None,
	public_key: Path | None = None) -> Path:
	artifact = artifact.resolve()
	signature = signature.resolve()
	manifest_path = (manifest_path or artifact.with_name("manifest.json")).resolve()
	if signature_type not in SUPPORTED_TYPES:
		raise ValueError(f"Unsupported signature type: {signature_type}")
	manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
	if manifest.get("filename") != artifact.name or not artifact.is_file() or not signature.is_file():
		raise ValueError("Artifact, signature, and manifest do not describe the same release.")
	if public_key is None or not public_key.is_file():
		raise ValueError("Ed25519 attachment requires the corresponding public key.")
	public_pem = public_key.read_bytes()
	verify_detached(artifact, signature_bytes(signature), public_pem)
	destination = artifact.with_name(f"{artifact.name}.{signature_type}.sig")
	shutil.copy2(signature, destination)
	manifest["signature_status"] = "SIGNED"
	manifest["integrity_status"] = "SIGNATURE_VERIFIED"
	manifest["signature_type"] = signature_type
	manifest["signature_file"] = destination.name
	manifest["signature_key_id"] = public_key_id(public_pem)
	manifest["signature_encoding"] = "base64"
	manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
	return destination


def main() -> None:
	parser = argparse.ArgumentParser(description="Attach a detached signature created by an external signing service")
	parser.add_argument("artifact", type=Path)
	parser.add_argument("signature", type=Path)
	parser.add_argument("--type", required=True, choices=sorted(SUPPORTED_TYPES))
	parser.add_argument("--manifest", type=Path)
	parser.add_argument("--public-key", required=True, type=Path)
	args = parser.parse_args()
	print(attach_signature(args.artifact, args.signature, args.type, args.manifest, args.public_key))


if __name__ == "__main__":
	main()
