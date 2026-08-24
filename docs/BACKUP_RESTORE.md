# Backup and restore

Use encrypted `pg_dump --format=custom` backups on a least-privileged scheduled host and periodically test `pg_restore` into an isolated PostgreSQL instance followed by `alembic upgrade head` and `/readiness`. Back up externally stored evidence/certificate/release directories with their checksums and retention policy. Do not include session tokens, agent credential files, database passwords, or signing private keys in ordinary artifact backups.

Before a local upgrade, preserve the configured local job SQLite database, outbox, evidence, and agent credential file with their ownership/mode. Restore them before restarting services; recovery conservatively resolves interrupted active work. Purging must be an explicit operator action after retention requirements are met and should use the platform's secure-deletion policy; uninstall does not silently erase evidence.
