# Release signing

Every release is SHA-256 verifiable with `vyper verify-package <artifact>`. An unsigned manifest reports `signature_status: UNSIGNED`, `integrity_status: CHECKSUM_ONLY`, `signature_type: null`, and must never be described as signed.

Signing is deliberately external to the source tree and PR workflow. A protected tagged-release job or offline release operator signs the completed archive using Ed25519, base64-encodes the detached signature, then runs:

`python packaging/attach_signature.py release/vyper-local-console-linux-x86_64-1.0.0-rc1.tar.gz /secure/output.sig --type ed25519 --public-key /secure/release-public.pem`

Stage 13 supports Ed25519 detached signatures. CI or an offline signing workstation receives the private key from an external secret manager, signs the final archive, and supplies only the base64 detached signature and public key to `packaging/attach_signature.py --type ed25519 --public-key ...`. The attachment step verifies the signature before updating the manifest.

The public verification key is shipped in `/opt/vyper/trust/trusted-release-keys.json`. Each identity is the SHA-256 fingerprint of the raw Ed25519 public key. Rotation adds a new trusted identity before releases switch signers. Revocation changes the compromised entry to `revoked`; verification refuses missing, mismatched, or revoked identities. Offline/manual signing follows the same detached-signature process. Private keys are never part of source, release artifacts, the SBOM, or database backups.
