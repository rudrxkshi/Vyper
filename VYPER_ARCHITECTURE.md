# VYPER Architecture

## Core Pipeline

Device Intake
→ Device Profiler
→ Capability Detection
→ Policy Engine
→ Sanitization Pathway
→ Verification
→ Evidence
→ Certificate
→ Disposition

## Storage Policy

### HDD
Default:
HDD host-level overwrite.

Optional:
ATA device-level erase when supported and explicitly selected.

### SATA SSD
Do not use ordinary host-level overwrite as the normal sanitization fallback.

Prefer cryptographic erase when supported and applicable.

Otherwise use an appropriate device-supported sanitization mechanism.

If no acceptable method exists:
UNSUPPORTED / MANUAL HANDLING.

### NVMe
Inspect device capabilities.

Prefer cryptographic erase when supported and applicable.

Otherwise select an appropriate supported NVMe sanitization mechanism.

Never assume every NVMe device supports the same mechanism.

Never silently fall back to generic host overwrite.

## NVMe SANICAP

bit 0 = Crypto Erase
bit 1 = Block Erase
bit 2 = Overwrite

## Core Separation

Profiler = WHAT?
Policy = WHICH?
Pathway = HOW?
Verifier = DID IT WORK?
Evidence = WHAT CAN WE PROVE?
Certificate = WHAT CAN WE CERTIFY?

## Fundamental Rule

Execution success does not automatically equal sanitization verification.

## Safety

No destructive operation without:
- explicit target
- device identity confirmation
- safety checks
- explicit authorization

Dry-run/mock mode must exist.

Unsupported/failed operations must never receive a successful sanitization certificate.