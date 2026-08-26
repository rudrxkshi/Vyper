# VYPER user dashboard

Install dependencies and run the development server:

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## Local mode

Local mode gets target devices from the dedicated local agent instead of the
central persisted asset inventory:

```bash
NEXT_PUBLIC_VYPER_MODE=local
NEXT_PUBLIC_VYPER_LOCAL_AGENT_API_BASE_URL=http://127.0.0.1:8765
npm run dev
```

The device selector shows discovery metadata and safety state. System devices
remain visible but cannot be selected for destructive execution. Mounted
devices display a warning and are never automatically unmounted.

## Central mode

Central mode is the default:

```bash
NEXT_PUBLIC_VYPER_MODE=central
NEXT_PUBLIC_VYPER_API_BASE_URL=http://127.0.0.1:8000
npm run dev
```

The Settings screen can persist a runtime URL/API-key override in browser local
storage. Local API version 2 returns an accepted job ID, and the dashboard polls
durable state until a terminal outcome. The latest local job ID is retained so
the detail view can be restored after a page refresh.

Central mode includes an Agents view for online/offline state, agent-owned
inventory, remote job creation, delivery state, local execution state, measured
progress, and verified final outcomes. Remote jobs select synchronized assets;
the browser cannot provide an arbitrary local device path.

When central synchronization is configured, local mode includes a Remote
requests view. Destructive requests remain pending until the local operator
approves them. The optional ATA password field is sent only to the loopback
local API for the immediate invocation and is cleared after submission.

The central build also exports `/download/`. Release data comes from central
`GET /downloads`; version, size, checksum, and URL are not duplicated in the UI.
The packaged local build is a static export served by `vyper-console` on
`127.0.0.1:8787`, never by `next dev` or `next start`.

## Verification

```bash
npm test
npm run lint
npm run build
```
