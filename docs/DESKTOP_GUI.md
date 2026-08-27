# VYPER Desktop GUI

The Linux local console uses a minimal Tauri v2 window around the existing
Next.js local-mode static export. The GUI is an unprivileged presentation
process. It calls the loopback-only local API at `http://127.0.0.1:8765` and
has no Tauri commands, shell bridge, block-device access, systemd control, or
privileged capabilities. Closing it does not stop the agent, executor, console
compatibility service, or an active sanitization job.

`vyper open` starts `/opt/vyper/gui/vyper-gui` when it is installed. If the
binary is unavailable or cannot start, the command falls back to the static
loopback console at `http://127.0.0.1:8787`. Port 8787 therefore remains a
compatibility/recovery path, but it is not required by the Tauri application.

## Linux development

Install the Tauri v2 Linux prerequisites, Rust stable, Node.js, and npm. On
Ubuntu/Debian, the WebKitGTK 4.1 development package and its GTK dependencies
are required by Tauri.

```bash
cd frontend/user-dashboard
npm ci
npm run desktop:dev
```

The development window uses the Next.js server on port 3000. The production
desktop build embeds a local-mode static export:

```bash
npm run desktop:check
npm run desktop:build
```

Run these commands as the desktop developer account, never as root. A complete
Linux release build invokes Cargo directly, copies only the resulting
`vyper-gui` executable into the release payload, and installs the application
launcher under `/usr/share/applications/vyper.desktop`.

## Manual installed-runtime validation

1. Confirm `systemctl status vyper-agent vyper-executor vyper-console` without
   changing their state.
2. As a non-root desktop user, run `vyper open` or select **VYPER Local
   Console** from the application menu.
3. Confirm the window has no browser address bar and the dashboard reports the
   local API connection state.
4. Confirm Dashboard, Remote requests, Assets, Jobs, Certificates, Audit logs,
   and Settings work as in the browser console.
5. Start only a mocked/dry-run job, close the window, reopen it, and confirm the
   service-owned job continued independently.
6. Temporarily stop the local agent, reopen the GUI, and confirm the dashboard
   reports the API as disconnected. Restart the service after the check.
7. Temporarily move `/opt/vyper/gui/vyper-gui`, run `vyper open`, and confirm
   the browser fallback opens `127.0.0.1:8787`; then restore the binary.
