# Final security invariant gate

Stage 14 reuses the full mocked/fixture regression suite; no destructive command is part of this gate.

| # | Invariant | Result and enforcement |
|---:|---|---|
| 1 | Browser cannot execute arbitrary root commands | PASS — fixed HTTP schemas; root helper accepts no argv. |
| 2 | Central cannot directly access local disks | PASS — outbound agent polling only. |
| 3 | Privileged executor has no network listener | PASS — AF_UNIX-only systemd and Python socket. |
| 4 | Root executor accepts typed allowlisted operations | PASS — discover/profile/sanitize schema validation. |
| 5 | Same target cannot run concurrent destructive jobs | PASS — database constraint and helper lock. |
| 6 | Remote destructive job requires authenticated MFA operator | PASS. |
| 7 | Remote authorization still requires local confirmation | PASS. |
| 8 | System disk is blocked in normal mode | PASS. |
| 9 | Boot mode re-identifies the target | PASS. |
| 10 | Unknown identity or safety refuses execution | PASS. |
| 11 | Interrupted execution cannot become VERIFIED | PASS. |
| 12 | VERIFIED requires verification/evidence/certificate integrity | PASS. |
| 13 | Agent revocation stops synchronization | PASS. |
| 14 | Secrets are absent from logs/artifacts | PASS — redaction and forbidden-file scans. |
| 15 | Boot-job replay is blocked | PASS. |
| 16 | Evidence/certificate mismatch is quarantined/refused | PASS. |

These are software security invariants, not proof of physical firmware behavior or deployment-specific key management.
