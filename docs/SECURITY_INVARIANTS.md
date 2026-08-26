# Security invariants

1. Browser and central APIs expose typed operations, never arbitrary root commands.
2. Central has no local disk pathway; local agents communicate outbound.
3. Central destructive authorization never bypasses local approval.
4. SQLite's partial unique target index prevents concurrent destructive jobs for one normalized target.
5. Interrupted or crashed workers become INCONCLUSIVE unless durable verification evidence was already committed.
6. VERIFIED requires agreeing job/final status, verification proof, evidence, and a supported certificate claim.
7. Revoked agents fail all future bearer-authenticated sync.
8. Centralized redaction and secret-bearing payload rejection keep secrets out of logs, audits, outbox, frontend, and artifacts.
9. System, mounted, eligibility, and identity state are re-discovered before remote execution. Unknown means unsafe.
10. The privileged process entry accepts a typed target, authorization object, dry-run flag, and job ID only; it never accepts command strings and does not use `shell=True`.
