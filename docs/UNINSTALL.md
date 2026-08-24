# Uninstall VYPER

Run `sudo ./uninstall.sh` to stop and remove services, commands, and application
files. This intentionally preserves `/etc/vyper`, `/var/lib/vyper`, and
`/var/log/vyper`, including credentials, job history, evidence, and outbox.

Run `sudo ./uninstall.sh --purge` only when those retained records should also
be permanently removed. Purge removes configuration, credentials, all local
job/outbox state, evidence, and logs.
