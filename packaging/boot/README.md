# VYPER boot artifact

`build_boot_image.py` builds the host-specific Ubuntu/Debian x86_64 kernel/initramfs artifact. The installed initramfs-tools hook supplies the VYPER runtime and required storage/network utilities; the local-premount script starts the console only for `vyper.mode=boot_sanitize`.

Use `--fixture` only for deterministic CI validation. Fixture artifacts are deliberately non-bootable and cannot be armed by `SystemDiskService`.
