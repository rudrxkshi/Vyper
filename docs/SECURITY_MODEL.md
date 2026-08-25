# VYPER Linux security model

`vyper-agent.service` runs as the unprivileged `vyper-agent` account. Linux
storage access is isolated in `vyper-executor.service`, a root fixed-function
helper reachable only through a group-restricted Unix-domain socket. Neither
service exposes a remote shell or arbitrary command endpoint.

`vyper-console.service` runs as the unprivileged `vyper-ui` service account and
serves a static production build on `127.0.0.1:8787`. Central synchronization
is outbound-only. Central browser authorization and local privileged approval
remain separate trust domains.

Configuration is mode `0640`. The agent credential is service-owned mode `0600`
and never enters the UI bundle, browser local storage, logs, diagnostic output,
or durable outbox. Private signing keys and the MFA encryption key remain
external deployment secrets.

Checksum-only releases remain supported; signed releases use externally
generated Ed25519 signatures. VYPER does not
provide system-disk boot sanitization, Windows/macOS packages, automatic
updates, or process isolation for native storage commands.
# Stage 13 production security controls

The local console, synchronization client, local API, and job persistence run as the unprivileged `vyper-agent` identity. A separate root service listens only on `/run/vyper/executor.sock`, owned by `root:vyper-executor` with mode `0660`. Its versioned protocol permits only discovery, profiling, and VYPER sanitization operations. It accepts no executable name, arbitrary argv, shell fragment, network connection, or arbitrary output path. The helper revalidates request shape, execution mode, authorization, `/dev` target, and same-target exclusivity before invoking the existing VYPER orchestrator.

Central password authentication remains supported. Enrolled operators then complete TOTP or consume a one-time recovery code. TOTP secrets are authenticated-encrypted with `VYPER_MFA_ENCRYPTION_KEY`; recovery codes are SHA-256 digests at rest. Destructive central job creation requires an ADMIN or OPERATOR session with `TOTP` or `RECOVERY` assurance. Sessions rotate after MFA, have idle and absolute expiry, use Secure/HttpOnly/SameSite cookies in production, and require a session-bound CSRF token for unsafe cookie-authenticated requests.

Release artifacts may use detached Ed25519 signatures. Trust comes only from `/opt/vyper/trust/trusted-release-keys.json` (or an explicitly configured replacement); a detached signature without a trusted matching key identity is rejected. No private key is stored or backed up by VYPER.
