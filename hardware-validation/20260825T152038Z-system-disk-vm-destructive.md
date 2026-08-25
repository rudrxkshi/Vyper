# VYPER destructive VirtualBox system-disk validation

- Workflow validation: **PASS**
- Virtual-disk sanitization validation: **PASS**
- Physical-media validation: **NOT_APPLICABLE**
- Boot job: `4edb1d85-ba87-4ee2-90d6-48808f00eaa6`
- VM: `vyper-stage11-disposable` (`de466510-ddae-4c3b-b1e1-adb5bb7482f1`)
- Target: `vbox harddisk` / `vb374dbc03-ecfa2108`
- Selected pathway: `HDD_OVERWRITE`
- Bytes written: `26843545600`
- Verifier: `VERIFIED` (8/8 samples passed)
- Evidence hash: `185e79cabb29e83f04c6bff48750f33314c5c4b6d8857977a08d80741591605e`
- Certificate hash: `5dfd721c82cc5db8434564a76df1ca221780068f5ede199644a41ca05e77fb37`
- Old Ubuntu bootable: **No**
- Sentinel accessible: **No**

## Independent post-check

The exact wiped VDI was attached to a separate disposable inspector. It had no partition table or filesystem signature, was never mounted, and 4 KiB samples at the beginning, middle, and end compared entirely zero. The evidence VDI was mounted `ro,norecovery` and the retained result, validation log, and reports were archived.

## Scope and warning

This proves the VYPER product flow against a disposable VirtualBox virtual disk. Physical-media validation is not applicable, and no physical HDD, SATA SSD, or NVMe device was tested. The VYPER boot console synchronized evidence and requested shutdown, but VirtualBox did not exit; host power-off was used only after evidence synchronization.
