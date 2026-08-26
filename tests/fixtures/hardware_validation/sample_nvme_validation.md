# VYPER controlled physical NVMe validation

- Conclusion: **PASS**
- Fixture: **MOCK ONLY — no physical device was tested**
- VYPER version: `1.0.0-rc1`
- Namespace: `/dev/nvme9n1`
- Controller: `/dev/nvme9`
- Sanitize scope: `controller`
- Controller namespaces: `/dev/nvme9n1`
- Sanitize target: `/dev/nvme9`
- Stable NGUID: `00112233445566778899aabbccddeeff`
- Model: `DISPOSABLE MOCK NVME`
- Serial: `MOCK-NVME-123456`
- Firmware: `1.0`

## Capability and method

- SANICAP: `7`
- Crypto erase: `true`
- Block erase: `true`
- Overwrite: `true`
- Policy-selected method: `CRYPTO_ERASE`
- Expected/actual SANACT: `4` / `4`

Mapping fixtures: `CRYPTO_ERASE → 4`, `BLOCK_ERASE → 2`, and
`NVME_OVERWRITE → 3`.

## Completion evidence

- Command submitted through mocked product API: `true`
- Controller structured SSTAT: `COMPLETED` (`raw=1`, `low_bits=1`)
- VYPER verification: `VERIFIED`
- Progress: `indeterminate`
- Evidence/certificate integrity and binding: `valid`
- Critical read-only probes: `succeeded`

## Conclusion

Validation basis: controller-reported completion of NVMe cryptographic sanitize.

## Limitations

- This is a mock report fixture, not physical validation evidence.
- Its scope is injected as proven only to exercise report logic. No physical
  execution was performed.
- Controller completion depends on firmware correctness.
- Host logical reads cannot prove every NAND location, spare/remapped block, or
  prior encryption-key state.
