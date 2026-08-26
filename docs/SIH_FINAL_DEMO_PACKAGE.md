# SIH final demo package

Use the [README](../README.md) for the product flow and architecture. Demonstrate the downloadable local console, local dashboard, central dashboard, outbound agent enrollment, device profiling, policy selection, and the HDD/ATA/NVMe method table in the [hardware matrix](HARDWARE_VALIDATION_MATRIX.md). Explain verification, evidence, certificates, and audit-chain integrity using the sanitized files in `demo-fixtures/`.

For system disks, reference the [VirtualBox validation guide](VIRTUALBOX_SYSTEM_DISK_VALIDATION.md) and retained destructive-VM summary; do not replay a destructive operation during a demo. The [threat model](THREAT_MODEL.md), [security gate](FINAL_SECURITY_GATE.md), [protocol freeze](PROTOCOL_VERSIONS.md), and [known limitations](KNOWN_LIMITATIONS.md) define the claim boundary.

Sustainability value comes from securely preparing storage for reuse rather than premature disposal. That benefit depends on correct operator identity checks and device-specific validation. State visibly that software and VirtualBox validation are complete while physical HDD, SATA SSD, NVMe, real Secure Boot, and deployment-specific production drills remain pending.
