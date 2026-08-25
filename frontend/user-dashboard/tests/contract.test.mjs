import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const goldenContract = JSON.parse(readFileSync(
  new URL("../../../tests/fixtures/stage8_api_contract.json", import.meta.url),
  "utf8",
));

import {
  ApiError,
  buildSanitizeRequest,
  checkBackendConnection,
  createApiClient,
  formatApiError,
  loadLocalJobId,
  saveLocalJobId,
} from "../lib/api.mjs";
import {
  auditLogView,
  certificateView,
  filterAssets,
  filterAuditLogs,
  formatBytes,
  getDeviceProtection,
  getFinalStatusMeta,
  getProgressPresentation,
  mountedPartitionsText,
  normalizeDiscoveredDevices,
  normalizeCentralJob,
  normalizeLocalJob,
  normalizeRemoteAgent,
  shouldPollLocalJob,
} from "../lib/presentation.mjs";

test("sanitize request matches the backend SanitizeJobCreate shape", async () => {
  const form = {
    target: "/dev/sdz",
    ataPassword: "temporary-password",
    dryRun: true,
    authorized: true,
  };
  const expected = {
    target: "/dev/sdz",
    authorization: {
      approved: true,
      ata_password: "temporary-password",
    },
    dry_run: true,
  };

  assert.deepEqual(buildSanitizeRequest(form), expected);
  assert.equal("authorized" in expected, false);
  assert.equal("ata_password" in expected, false);

  let submittedBody;
  const client = createApiClient({
    baseUrl: "http://test.invalid",
    fetchImpl: async (_url, options) => {
      submittedBody = JSON.parse(options.body);
      return new Response(JSON.stringify({ id: "job-1" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    },
  });
  await client.createSanitizeJob(form);
  assert.deepEqual(submittedBody, expected);
});

test("shared Stage 8 golden contract preserves API and boot protocol versions", () => {
  assert.deepEqual(buildSanitizeRequest({
    target: "/dev/sdb", ataPassword: "", dryRun: false, authorized: true,
  }), goldenContract.local_sanitize_request);
  assert.equal(goldenContract.versions.local_api, "2");
  assert.equal(goldenContract.versions.agent_protocol, "1");
  assert.equal(goldenContract.central_job_create.execution_mode, "boot_sanitize");
  assert.equal(goldenContract.boot_lifecycle_event.state, "BOOT_ENVIRONMENT_STARTED");
});

test("empty ATA password is represented as null", () => {
  assert.equal(
    buildSanitizeRequest({
      target: "/dev/sdz",
      ataPassword: "",
      dryRun: true,
      authorized: false,
    }).authorization.ata_password,
    null,
  );
});

test("VERIFIED is the successful final status", () => {
  const status = getFinalStatusMeta("VERIFIED");
  assert.equal(status.successful, true);
  assert.equal(status.tone, "ok");
  assert.equal(status.label, "Verified");
});

test("certificate fixture uses backend response fields", () => {
  const fixture = {
    certificate_id: "cert-1",
    certificate_hash: "sha256-value",
    successful_sanitization_claim: true,
    outcome_kind: "sanitization_certificate",
    final_status: "VERIFIED",
    certificate_json: {
      certificate_version: "1.0.0",
      issued_at: "2026-01-01T00:00:00Z",
    },
  };

  assert.deepEqual(certificateView(fixture), {
    certificateId: "cert-1",
    certificateHash: "sha256-value",
    successfulClaim: true,
    outcomeKind: "sanitization_certificate",
    certificateJson: fixture.certificate_json,
    title: "Sanitization certificate",
    detail: "Verification succeeded",
    tone: "ok",
  });
});

test("unsuccessful outcome report is not labeled a sanitization certificate", () => {
  const view = certificateView({
    certificate_id: "report-1",
    certificate_hash: "hash",
    successful_sanitization_claim: false,
    outcome_kind: "outcome_report",
    final_status: "INCONCLUSIVE",
    certificate_json: {},
  });

  assert.equal(view.title, "Outcome report");
  assert.equal(view.detail, "Verification inconclusive");
  assert.notEqual(view.title, "Sanitization certificate");
});

test("audit fixture uses backend response fields and request target", () => {
  const fixture = {
    id: "audit-1",
    action: "sanitize_device",
    actor: "operator@example.test",
    request_json: { target: "/dev/sdz", dry_run: true },
    response_json: { job_state: "VERIFIED" },
    created_at: "2026-01-01T00:00:00Z",
  };

  assert.deepEqual(auditLogView(fixture), {
    action: "sanitize_device",
    actor: "operator@example.test",
    target: "/dev/sdz",
    requestJson: fixture.request_json,
    responseJson: fixture.response_json,
    createdAt: "2026-01-01T00:00:00Z",
  });
});

test("nullable asset and audit fields do not crash filtering", () => {
  const assets = [
    {
      id: "asset-1",
      model: null,
      serial_number: null,
      device_type: null,
      target: null,
      mounted: false,
    },
  ];
  const logs = [{ id: "audit-1", actor: null, action: "sanitize_device" }];

  assert.deepEqual(filterAssets(assets, { search: "missing" }), []);
  assert.deepEqual(filterAssets(assets, { search: "" }), assets);
  assert.deepEqual(filterAuditLogs(logs, { actor: "missing" }), []);
  assert.deepEqual(filterAuditLogs(logs, { actor: "" }), logs);
});

test("discovered devices normalize into target-selector records", () => {
  const [device] = normalizeDiscoveredDevices([{
    device_path: "/dev/sdb",
    model: null,
    serial_number: null,
    size_bytes: 1000000000,
    device_type: "SSD",
    mounted_partitions: [],
    is_system_device: false,
  }]);

  assert.equal(device.id, "/dev/sdb");
  assert.equal(device.device_path, "/dev/sdb");
  assert.equal(device.model, null);
  assert.equal(device.serial_number, null);
  assert.equal(formatBytes(device.size_bytes), "953.7 MiB");
});

test("system devices are visible but protected from destructive execution", () => {
  const protection = getDeviceProtection({
    device_path: "/dev/sda",
    is_system_device: true,
    profile_error: null,
    mounted: true,
  });

  assert.equal(protection.blocked, true);
  assert.equal(
    protection.reason,
    "This is the system disk and cannot be wiped from the currently running operating system.",
  );
});

test("mounted devices expose a warning and readable mount list", () => {
  const protection = getDeviceProtection({
    device_path: "/dev/sdb",
    is_system_device: false,
    profile_error: null,
    mounted: true,
  });

  assert.equal(protection.blocked, false);
  assert.match(protection.warning, /mounted filesystems/i);
  assert.equal(
    mountedPartitionsText([{ path: "/dev/sdb1", mountpoint: "/data" }]),
    "/dev/sdb1 at /data",
  );
});

test("an explicitly ineligible discovery record is not treated as safe", () => {
  const protection = getDeviceProtection({
    device_path: "/dev/sdc",
    is_system_device: false,
    profile_error: null,
    eligible_for_sanitization: false,
    mounted: false,
  });

  assert.equal(protection.blocked, true);
  assert.match(protection.reason, /did not establish/i);
});

test("local agent job responses normalize into dashboard records", () => {
  const job = normalizeLocalJob({
    api_version: "1",
    local_job_id: "local-1",
    target: "/dev/sdb",
    job_state: "VERIFIED",
    final_status: "VERIFIED",
    execution: { dry_run: true },
    policy: { selected_pathway: "HDD_OVERWRITE" },
    certificate: {},
  });

  assert.equal(job.id, "local-1");
  assert.equal(job.dry_run, true);
  assert.equal(job.pathway, "HDD_OVERWRITE");
  assert.equal(job.certificate, null);
});

test("async accepted jobs remain pending and are polled", () => {
  const job = normalizeLocalJob({
    api_version: "2",
    local_job_id: "local-pending",
    target: "/dev/sdb",
    dry_run: false,
    job_state: "PENDING",
    final_status: null,
  });

  assert.equal(job.final_status, null);
  assert.equal(shouldPollLocalJob(job), true);
  assert.equal(shouldPollLocalJob({ ...job, job_state: "VERIFIED" }), false);
});

test("percentage is shown only for trustworthy numeric byte progress", () => {
  const measured = getProgressPresentation({
    kind: "bytes",
    bytes_completed: 25,
    bytes_total: 100,
  });
  const firmware = getProgressPresentation({ kind: "indeterminate", percentage: 88 });

  assert.equal(measured.kind, "bytes");
  assert.equal(measured.percentage, 25);
  assert.equal(firmware.kind, "indeterminate");
  assert.equal(firmware.percentage, null);
});

test("local job id survives page-refresh storage", () => {
  const values = new Map();
  const storage = {
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value),
    removeItem: (key) => values.delete(key),
  };

  saveLocalJobId(storage, "local-refresh");
  assert.equal(loadLocalJobId(storage), "local-refresh");
});

test("successful health response produces connected state", async () => {
  assert.equal(await checkBackendConnection({ health: async () => true }), true);
});

test("failed health response produces disconnected state", async () => {
  assert.equal(
    await checkBackendConnection({
      health: async () => {
        throw new Error("offline");
      },
    }),
    false,
  );
});

test("local-mode client rejects a central service identity", async () => {
  const client = createApiClient({
    baseUrl: "http://test.invalid",
    expectedService: "local-agent",
    fetchImpl: async () => new Response(
      JSON.stringify({ status: "ok", service: "central", api_version: "1" }),
      { status: 200, headers: { "content-type": "application/json" } },
    ),
  });

  assert.equal(await checkBackendConnection(client), false);
});

test("central remote jobs use an agent-owned synchronized asset contract", async () => {
  let requestedUrl;
  let requestedBody;
  const client = createApiClient({
    baseUrl: "http://central.invalid",
    fetchImpl: async (url, options) => {
      requestedUrl = url;
      requestedBody = JSON.parse(options.body);
      return new Response(JSON.stringify({ central_job_id: "central-1" }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const payload = {
    asset_id: "asset-1",
    dry_run: false,
    central_authorized: true,
    destructive_confirmation: "SANITIZE",
    idempotency_key: "browser-request-1",
    expires_in_seconds: 3600,
  };
  await client.createCentralJob("agent/one", payload);

  assert.equal(requestedUrl, "http://central.invalid/agents/agent%2Fone/jobs");
  assert.deepEqual(requestedBody, payload);
  assert.equal("target" in requestedBody, false);
});

test("central operator requests include the HttpOnly session cookie", async () => {
  let requestOptions;
  const client = createApiClient({
    baseUrl: "https://central.example/api",
    fetchImpl: async (_url, options) => {
      requestOptions = options;
      return new Response(JSON.stringify({ username: "operator", role: "OPERATOR" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  await client.currentUser();
  assert.equal(requestOptions.credentials, "include");
});

test("agent and central job normalization preserve remote lifecycle state", () => {
  const agent = normalizeRemoteAgent({
    agent_id: "agent-1",
    status: "ONLINE",
    asset_count: 2,
    active_jobs: 1,
    verified_jobs: 4,
  });
  const job = normalizeCentralJob({
    central_job_id: "central-1",
    status: "WAITING_LOCAL_APPROVAL",
    local_execution_state: null,
    final_status: null,
    progress: { kind: "bytes", bytes_completed: 50, bytes_total: 100 },
  });

  assert.equal(agent.id, "agent-1");
  assert.equal(agent.online, true);
  assert.equal(job.waiting_local_approval, true);
  assert.equal(job.job_state, "WAITING_LOCAL_APPROVAL");
  assert.equal(job.final_status, null);
  assert.equal(getProgressPresentation(job.progress).percentage, 50);
});

test("central dashboard preserves system-disk boot lifecycle and execution mode", () => {
  const job = normalizeCentralJob({
    central_job_id: "central-boot-1",
    execution_mode: "boot_sanitize",
    status: "WAITING_LOCAL_APPROVAL",
    boot_lifecycle: "WAITING_LOCAL_APPROVAL",
    final_status: null,
  });

  assert.equal(job.execution_mode, "boot_sanitize");
  assert.equal(job.boot_lifecycle, "WAITING_LOCAL_APPROVAL");
  assert.equal(job.waiting_local_approval, true);
});

test("local approval request sends only explicit approval and transient ATA password", async () => {
  let requestedUrl;
  let requestedBody;
  const client = createApiClient({
    baseUrl: "http://local.invalid",
    fetchImpl: async (url, options) => {
      requestedUrl = url;
      requestedBody = JSON.parse(options.body);
      return new Response(JSON.stringify({ status: "SUBMITTED" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  await client.approveRemoteJob("central/job", {
    approved: true,
    ata_password: "transient-only",
  });

  assert.equal(requestedUrl, "http://local.invalid/remote-jobs/central%2Fjob/approve");
  assert.deepEqual(requestedBody, { approved: true, ata_password: "transient-only" });
});

test("download metadata is loaded from the central release endpoint", async () => {
  let requestedUrl;
  const fixture = [{
    version: "1.0.0-rc1",
    platform: "linux",
    architecture: "x86_64",
    filename: "vyper-local-console-linux-x86_64-1.0.0-rc1.tar.gz",
    sha256: "a".repeat(64),
    size_bytes: 1234,
    download_url: "/downloads/vyper-local-console-linux-x86_64-1.0.0-rc1.tar.gz",
  }];
  const client = createApiClient({
    baseUrl: "https://central.example",
    fetchImpl: async (url) => {
      requestedUrl = url;
      return new Response(JSON.stringify(fixture), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  assert.deepEqual(await client.listDownloads(), fixture);
  assert.equal(requestedUrl, "https://central.example/downloads");
  assert.equal(fixture.some((item) => item.platform === "windows"), false);
});

test("FastAPI validation details retain HTTP status and safe field messages", () => {
  const error = new ApiError(
    "body.authorization: Field required",
    422,
    [{ loc: ["body", "authorization"], msg: "Field required" }],
  );
  assert.equal(formatApiError(error), "HTTP 422: body.authorization: Field required");
});
