# VYPER 1.0.0-rc1 release freeze

Release version: `1.0.0-rc1`  
Source baseline inspected: commit `539250dca43c03eb96a0940497d215cb1807cb9e` on branch `yash-changes`  
Expected release tag: annotated tag `v1.0.0-rc1` on the final reviewed release commit  
Freeze preparation timestamp: `2026-08-26T00:00:00+05:30`  
Supported package platform: Linux x86_64; Ubuntu is the validated build/boot environment and Debian is compatible but not equivalently boot-validated.

Frozen interfaces are Local API v2, agent protocol v1, privileged-executor protocol v1, boot-manifest schema v1, evidence structural schema v1, certificate schema `1.0.0`, local job-store schema 2, and Alembic head `0009_merge_migration_heads`.

The source baseline above was dirty while Stage 14 was prepared. The release manager must review and commit the complete RC tree, record that resulting commit in release records, build from a clean checkout, and place `v1.0.0-rc1` on that exact commit. Do not modify sanitization code after the freeze except for a documented release-blocking correctness or security defect. Do not tag or push automatically.

If a tag-signing identity exists, use `git tag -s v1.0.0-rc1 -m "VYPER 1.0.0-rc1"`. Otherwise use `git tag -a v1.0.0-rc1 -m "VYPER 1.0.0-rc1 (unsigned annotated RC tag)"` and record that the tag is unsigned.
