# Secure Boot

Stage 7 does not claim universal Secure Boot compatibility. Before arming GRUB, VYPER queries `mokutil --sb-state`. When Secure Boot is enabled, an image whose kernel manifest is not marked as signed by a trusted key is refused.

The host build detects a PE/COFF kernel signature with `sbverify`, but that alone cannot prove that every firmware trusts its signer or that a platform permits the generated initramfs/GRUB chain. Test the artifact on the intended hardware and enrolled keys. A future release should add a managed signing and key-enrollment workflow.

Do not permanently disable Secure Boot merely to use this prototype without first evaluating the loss of boot-chain protection. If organizational policy permits a temporary change, record and restore it through the hardware's documented process; VYPER does not automate that change.

Run `vyper system-disk secure-boot-status --certificate /path/to/MOK.der` for a read-only assessment. `SUPPORTED` means Secure Boot is enabled and `mokutil --test-key` confirms the configured public certificate is enrolled. `REQUIRES_KEY_ENROLLMENT` means shim/MOK enrollment is still required. `UNSUPPORTED` means Secure Boot is disabled without VYPER changing it. `UNKNOWN` means state could not be established. Kernel/initramfs or UKI signing material must be supplied externally; private signing keys are never packaged.
