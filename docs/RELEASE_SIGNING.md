# Release signing

Every release is SHA-256 verifiable with `vyper verify-package <artifact>`. An unsigned manifest reports `signature_status: checksum-only`, `signature_type: null`, and must never be described as signed.

Signing is deliberately external to the source tree and PR workflow. A protected tagged-release job or offline release operator signs the completed archive using minisign, cosign, or GPG, then runs:

`python packaging/attach_signature.py release/vyper-local-console-linux-x86_64.tar.gz /secure/output.sig --type minisign`

This copies the detached signature and marks its type in the manifest; it never reads a private key. Public-key cryptographic verification is a future extension. Current `verify-package` verifies SHA-256 and truthfully reports whether detached signature metadata is present, but does not claim the signature is cryptographically verified. Never store private signing keys or base64-encoded key material in the repository or ordinary build artifacts.
