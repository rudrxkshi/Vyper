# Controlled physical NVMe validation

Use this harness only with one explicitly selected, disposable, non-system NVMe
namespace. It is plan-only unless `--execute` and the exact identity-derived
confirmation are both supplied:

```text
sudo vyper validate-hardware nvme --device /dev/nvme0n1
sudo vyper validate-hardware nvme prepare --device /dev/nvme0n1
```

Preparation creates a small ext4 filesystem, mounts it, writes deterministic
files and SHA-256 hashes, syncs, and unmounts it. It does not fill the device and
requires `PREPARE <identity-suffix>` confirmation.

## Namespace and controller scope

The selected storage asset remains a namespace. VYPER resolves its owning
controller from Linux sysfs topology and records the identities separately:

```text
requested_namespace: /dev/nvme0n1
resolved_controller: /dev/nvme0
sanitize_scope: controller
controller_namespaces:
  - /dev/nvme0n1
sanitize_target: /dev/nvme0
```

Both `nvme sanitize` and `nvme sanitize-log` use the proven controller character
device, as required by the [nvme-cli sanitize documentation](https://github.com/linux-nvme/nvme-cli/blob/master/Documentation/nvme-sanitize.txt).
The namespace remains the asset and evidence identity; it is never changed into
the controller path.

Sanitize is controller-scoped and must not be represented as isolated to one
namespace. VYPER enumerates all controller namespaces and checks each using
read-only classification, system-device, mount, swap, LVM, mdraid,
device-mapper, multipath, and holder inspection. Unknown state refuses
execution. This first safe implementation always refuses a controller exposing
more than one namespace, even if every namespace appears idle, because explicit
controller-wide impact is not yet modeled.

## Capabilities and method mapping

SANICAP is read from controller identify data. Namespace-only metadata and NVMe
device type are not proof of controller sanitize support. The mappings remain:

| Policy-selected method | Controller SANACT |
|---|---:|
| `CRYPTO_ERASE` | 4 |
| `BLOCK_ERASE` | 2 |
| `NVME_OVERWRITE` / `OVERWRITE` | 3 |

The harness reports the mapping but never constructs or directly runs the
sanitize command. Eligible execution submits through local API v2, durable job,
`VYPERAgent`, policy, `NVMeSanitizePathway`, verifier, evidence, and certificate.
Unsupported controller SANICAP stops execution with no fallback.

## Identity and safety gates

Namespace identity includes NGUID, EUI-64, UUID, namespace ID, and capacity.
Controller identity includes path, serial, model, firmware, and PCI/sysfs
identity. Stable namespace identity preference is NGUID, EUI-64, UUID, then
controller serial + model + namespace ID + capacity. A `/dev/nvme0n1` path alone
is never identity.

Before execution VYPER requires an exact namespace with no wildcard or
partition; unambiguous namespace-to-controller topology; exactly one enumerated
controller namespace; stable namespace and controller identity; unchanged
capacity; non-system and unmounted state across the controller; no active
dependency; reachable controller; controller SANICAP support; and exact SANACT
mapping. It repeats profiling, topology, identity, SANICAP, and policy checks
after exact `ERASE <identity-suffix>` confirmation. Any change stops execution.

## Completion and evidence

Command acceptance is not completion. Reports preserve separate
`command_submission_result`, `controller_completion_result`, and
`verification_result` fields. Execution metadata records requested namespace,
resolved controller, controller namespaces, controller sanitize target,
`sanitize_scope: controller`, selected method, and effective SANACT.

The verifier runs structured `nvme sanitize-log <controller>
--output-format=json`, parses SSTAT, and masks `raw & 0x7`. COMPLETED is a
VERIFIED candidate; IN_PROGRESS is inconclusive; FAILED and textually identified
ABORTED fail; malformed or missing SSTAT is inconclusive. Bit 8
(`global_data_erased`) alone is never success. ABORTED currently depends on an
abort textual hint attached to structured SSTAT.

Polling records timestamp, raw safe JSON, raw SSTAT, low status bits, normalized
state, global-data-erased bit, and status text. Progress remains indeterminate;
elapsed time is never converted into a percentage and sanitize is never
automatically resubmitted.

Read-only post-checks include controller/namespace identify, sanitize-log,
`lsblk -f`, `blkid -p`, `file -s`, and `udevadm info`. Logical reads are
secondary and cannot independently observe every NAND location, spare or
remapped block, or encryption-key state. Crypto reports therefore claim only
“controller-reported completion of NVMe cryptographic sanitize.” Controller
firmware remains a trust boundary.

A reset or asynchronous sanitize may temporarily remove a controller or
namespace. Temporary absence is recorded rather than automatically treated as
failure, but it never becomes VERIFIED without later structured COMPLETED.
Timeout leaves completion unproven and does not trigger another sanitize.

## Operator checklist

1. Use directly attached disposable media and independently confirm backups.
2. Run the read-only plan and inspect both namespace and controller identities.
3. Confirm SANICAP, policy-selected method, and SANACT agree.
4. Confirm exactly one controller namespace is listed and all safety state is known.
5. Stop for any holder, mount, swap, system association, ambiguity, or identity change.
6. If needed, review the prepare plan and use exact PREPARE confirmation.
7. Re-plan after preparation and confirm the namespace is unmounted.
8. Require `Sanitize scope: controller`, controller target, and `ELIGIBLE`.
9. Use `--execute`, type the exact ERASE phrase, and do not power-cycle the device.
10. Preserve JSON, Markdown, evidence, and certificate artifacts with their stated limitations.
