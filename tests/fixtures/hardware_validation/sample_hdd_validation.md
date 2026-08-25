# VYPER controlled physical HDD validation — mock fixture

> This is a report-shape fixture. No physical drive was tested.

- Conclusion: **PASS (mock inputs only)**
- VYPER version: `1.0.0-rc1`
- Device: `/dev/sdz`
- Model: `DISPOSABLE MOCK HDD`
- Serial: `MOCK-HDD-123456`
- Capacity: `5368709120` bytes

## Product-path result

- Local job: `mock-local-job`
- Selected pathway: `HDD_OVERWRITE`
- VYPER final status: `VERIFIED`
- Measured progress records: `2`
- Evidence and certificate fixture hashes: present and mutually bound in the mock input

## Independent post-checks

- Filesystem detected: `false`
- `blkid` signature detected: `false`
- Beginning/middle/end logical samples match zero: `true`

## Conclusion

Known test data is no longer accessible through the logical block interface and sampled regions match the expected overwrite pattern.

This fixture does not prove physical-media behavior. Logical read sampling does not prove every physical magnetic sector or domain independently.
