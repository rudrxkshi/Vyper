# VYPER Linux security model

`vyper-agent.service` runs as root because Linux storage sanitization requires
privileged device access. Its FastAPI surface binds to `127.0.0.1` by default,
accepts only typed VYPER operations, validates explicit `/dev` targets, and
retains mounted/system-device and authorization protections. It has no remote
shell or arbitrary command endpoint.

`vyper-console.service` runs as the unprivileged `vyper-ui` service account and
serves a static production build on `127.0.0.1:8787`. Central synchronization
is outbound-only. Central browser authorization and local privileged approval
remain separate trust domains.

Configuration is mode `0640`. The agent credential is root-owned mode `0600`
and never enters the UI bundle, browser local storage, logs, diagnostic output,
or durable outbox. A future release should split synchronization from the
privileged executor and use systemd credentials or an OS-backed secret store.

Stage 5 provides checksum integrity only, not package signing. It does not
provide system-disk boot sanitization, Windows/macOS packages, automatic
updates, or process isolation for native storage commands.
