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
  readCookie,
  saveLocalJobId,
} from "../lib/api.mjs";
import {
  auditLogView,
  auditLogsForJob,
  certificateView,
  filterAssets,
  filterAuditLogs,
  formatBytes,
  getDeviceProtection,
  getFinalStatusMeta,
  getPipelinePresentation,
  getProgressPresentation,
  mountedPartitionsText,
  mergeCentralJobList,
  normalizeDiscoveredDevices,
  normalizeCentralJob,
  normalizeLocalJob,
  remoteAssetsForJob,
  normalizeRemoteAgent,
  preferCentralJobSnapshot,
  shouldPollCentralJob,
  shouldPollLocalJob,
  upsertCentralJob,
} from "../lib/presentation.mjs";
import { loadLocalConsoleData } from "../lib/local-console-data.mjs";
import { releaseDownloadUrl, selectLinuxX64Release } from "../lib/downloads.mjs";

const pipelineStatuses = (history, jobState = "RUNNING") =>
  getPipelinePresentation(history.map((state, index) => ({ sequence: index + 1, state })), jobState)
    .map((stage) => stage.status);

test("pipeline presentation advances only from persisted stage milestones", () => {
  const events = [];
  events.push("STAGE_PROFILING_STARTED");
  assert.deepEqual(pipelineStatuses(events), ["current", "pending", "pending", "pending", "pending", "pending"]);
  events.push("STAGE_PROFILING_COMPLETED", "STAGE_POLICY_STARTED");
  assert.deepEqual(pipelineStatuses(events), ["done", "current", "pending", "pending", "pending", "pending"]);
  events.push("STAGE_POLICY_COMPLETED", "STAGE_EXECUTION_STARTED");
  assert.deepEqual(pipelineStatuses(events), ["done", "done", "current", "pending", "pending", "pending"]);
  events.push("STAGE_EXECUTION_COMPLETED", "STAGE_VERIFICATION_STARTED");
  assert.deepEqual(pipelineStatuses(events), ["done", "done", "done", "current", "pending", "pending"]);
  events.push("STAGE_VERIFICATION_COMPLETED", "STAGE_EVIDENCE_STARTED");
  assert.deepEqual(pipelineStatuses(events), ["done", "done", "done", "done", "current", "pending"]);
  events.push("STAGE_EVIDENCE_COMPLETED", "STAGE_CERTIFICATE_STARTED");
  assert.deepEqual(pipelineStatuses(events), ["done", "done", "done", "done", "done", "current"]);
  events.push("STAGE_CERTIFICATE_COMPLETED");
  assert.deepEqual(pipelineStatuses(events, "VERIFIED"), ["done", "done", "done", "done", "done", "done"]);
});

test("pipeline failure and terminal state do not synthesize later completion", () => {
  const failed = [
    "STAGE_PROFILING_STARTED", "STAGE_PROFILING_COMPLETED",
    "STAGE_POLICY_STARTED", "STAGE_POLICY_COMPLETED",
    "STAGE_EXECUTION_STARTED", "STAGE_EXECUTION_FAILED",
  ];
  assert.deepEqual(pipelineStatuses(failed, "FAILED"), ["done", "done", "bad", "pending", "pending", "pending"]);
  assert.deepEqual(pipelineStatuses(["VERIFIED"], "VERIFIED"), ["pending", "pending", "pending", "pending", "pending", "pending"]);
});

test("central normalization keeps live events when no final result history exists", () => {
  const events = [{ sequence: 1, state: "STAGE_PROFILING_STARTED" }];
  const job = normalizeCentralJob({
    central_job_id: "central-live", requested_target: "/dev/sdb", events,
    result: { state_history: [] }, local_execution_state: "PROFILING",
  });
  assert.deepEqual(job.state_history_json, events);
});

test("dashboard pipeline receives persisted event history", () => {
  const source = readFileSync(new URL("../app/page.js", import.meta.url), "utf8");
  assert.match(source, /eventHistory=\{selectedJob\.state_history_json\}/);
  assert.doesNotMatch(source, /meta\.successful/);
});

test("central job detail associates null-job-id audits by central resource while preserving legacy lookup", () => {
  const audits = [
    { id: "central-audit", job_id: null, resource: "central-job:central-1", action: "RESULT_ACCEPTED" },
    { id: "other-central", job_id: null, resource: "central-job:central-2", action: "RESULT_ACCEPTED" },
    { id: "legacy-audit", job_id: "legacy-1", resource: "job:legacy-1", action: "JOB_COMPLETED" },
  ];
  const central = normalizeCentralJob({ central_job_id: "central-1", requested_target: "/dev/sdb" });
  assert.deepEqual(auditLogsForJob(central, audits).map((entry) => entry.id), ["central-audit"]);
  assert.deepEqual(auditLogsForJob({ id: "legacy-1" }, audits).map((entry) => entry.id), ["legacy-audit"]);
});

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

test("ATA password is only sent while destructive approval is enabled", () => {
  assert.deepEqual(buildSanitizeRequest({
    target: "/dev/sdz",
    ataPassword: "stale-password",
    dryRun: false,
    authorized: false,
  }).authorization, {
    approved: false,
    ata_password: null,
  });
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

test("destructive remote selector excludes unsafe assets without changing inventory", () => {
  const assets = [
    { id: "system", device_path: "/dev/sda", profile_json: { is_system_device: true, mounted: true, eligible_for_sanitization: false } },
    { id: "mounted", device_path: "/dev/sdc", profile_json: { is_system_device: false, mounted: true, eligible_for_sanitization: true } },
    { id: "ineligible", device_path: "/dev/sdd", profile_json: { is_system_device: false, mounted: false, eligible_for_sanitization: false } },
    { id: "eligible", device_path: "/dev/sdb", profile_json: { is_system_device: false, mounted: false, eligible_for_sanitization: true } },
  ];

  assert.deepEqual(
    remoteAssetsForJob(assets, { dryRun: false, executionMode: "normal_local" }).map((asset) => asset.id),
    ["eligible"],
  );
  assert.equal(remoteAssetsForJob(assets, { dryRun: true, executionMode: "normal_local" }).length, 4);
  assert.equal(assets.length, 4);
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
  assert.equal(shouldPollLocalJob({ ...job, job_state: "REJECTED" }), false);
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

test("local console reads certificate and lifecycle projections from local endpoints", async () => {
  const requestedUrls = [];
  const client = createApiClient({
    baseUrl: "http://127.0.0.1:8765",
    expectedService: "local-agent",
    fetchImpl: async (url) => {
      requestedUrls.push(url);
      return new Response(JSON.stringify([]), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  assert.deepEqual(await client.listCertificates(), []);
  assert.deepEqual(await client.listAuditLogs(), []);
  assert.deepEqual(requestedUrls, [
    "http://127.0.0.1:8765/certificates",
    "http://127.0.0.1:8765/audit-logs",
  ]);
});

test("populated local certificate and audit arrays survive the dashboard loading boundary", async () => {
  const certificate = { id: "local:job-1:cert-1", certificate_id: "cert-1", local_job_id: "job-1" };
  const audit = { id: "local:job-1:1", local_job_id: "job-1", sequence: 1, action: "LOCAL_JOB_PENDING" };
  const localData = await loadLocalConsoleData({
    listDevices: async () => [],
    listJobs: async () => [],
    listCertificates: async () => [certificate],
    listAuditLogs: async () => [audit],
    listRemoteJobs: async () => [],
    getSyncStatus: async () => ({ configured: false }),
  });

  assert.deepEqual(localData.certificates, [certificate]);
  assert.deepEqual(localData.auditLogs, [audit]);
});

test("local collection loader rejects central-style wrapper objects", async () => {
  await assert.rejects(() => loadLocalConsoleData({
    listDevices: async () => [],
    listJobs: async () => [],
    listCertificates: async () => ({ items: [] }),
    listAuditLogs: async () => [],
    listRemoteJobs: async () => [],
    getSyncStatus: async () => ({}),
  }), /certificates response must be a JSON array/i);
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

test("central API client restores the readable CSRF token after page reload", async () => {
  const originalDocument = globalThis.document;
  globalThis.document = { cookie: "unrelated=value; vyper_csrf=reload-token%2Fsafe" };
  let requestOptions;
  try {
    const client = createApiClient({
      baseUrl: "https://central.example",
      fetchImpl: async (_url, options) => {
        requestOptions = options;
        return new Response(JSON.stringify({ central_job_id: "central-1" }), {
          status: 200,
          headers: { "content-type": "application/json" },
        });
      },
    });
    await client.decideCentralJob("central-1", "APPROVED");
  } finally {
    if (originalDocument === undefined) delete globalThis.document;
    else globalThis.document = originalDocument;
  }
  assert.equal(readCookie("vyper_csrf", "vyper_csrf=reload-token%2Fsafe"), "reload-token/safe");
  assert.equal(new Headers(requestOptions.headers).get("X-CSRF-Token"), "reload-token/safe");
});

test("central security policy and approval APIs preserve scoped contracts", async () => {
  const requests = [];
  const client = createApiClient({
    baseUrl: "https://central.example",
    fetchImpl: async (url, options = {}) => {
      requests.push({ url, method: options.method || "GET", body: options.body ? JSON.parse(options.body) : null });
      return new Response(JSON.stringify([]), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  await client.listOrganizations();
  await client.listPolicies("organization/one");
  await client.listSecurityEvents();
  await client.decideCentralJob("central/job", "APPROVED");
  await client.changePassword("NewTestPassword123!");
  assert.deepEqual(requests, [
    { url: "https://central.example/organizations", method: "GET", body: null },
    { url: "https://central.example/organizations/organization%2Fone/policies", method: "GET", body: null },
    { url: "https://central.example/security-events", method: "GET", body: null },
    { url: "https://central.example/central-jobs/central%2Fjob/approvals", method: "POST", body: { decision: "APPROVED" } },
    { url: "https://central.example/auth/debug/password", method: "POST", body: { password: "NewTestPassword123!" } },
  ]);
});

test("central dashboard wires MFA policy security and approval workflows", () => {
  const source = readFileSync(new URL("../app/page.js", import.meta.url), "utf8");
  assert.match(source, /mfa_required/);
  assert.match(source, /Verify multi-factor authentication/);
  assert.match(source, /policy_id: selectedRemotePolicy/);
  assert.match(source, /screen === "policies"/);
  assert.match(source, /screen === "security-events"/);
  assert.match(source, /decideCentralJob\(job, "APPROVED"\)/);
  assert.match(source, /last heartbeat/);
  assert.match(source, /changeDebugPassword/);
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

test("new pending remote requests survive refresh beside older submitted requests", async () => {
  const older = { central_job_id: "older", status: "SUBMITTED", local_job_id: "local-old" };
  const pending = { central_job_id: "new", status: "WAITING_LOCAL_APPROVAL", local_job_id: null, dry_run: false };
  const localData = await loadLocalConsoleData({
    listDevices: async () => [],
    listJobs: async () => [],
    listCertificates: async () => [],
    listAuditLogs: async () => [],
    listRemoteJobs: async () => [pending, older],
    getSyncStatus: async () => ({ configured: true }),
  });

  assert.deepEqual(localData.remoteRequests, [pending, older]);
  assert.equal(localData.remoteRequests[0].status, "WAITING_LOCAL_APPROVAL");
  const source = readFileSync(new URL("../app/page.js", import.meta.url), "utf8");
  assert.match(source, /setInterval\(\(\) => refreshDashboardData\(\), 8000\)/);
  assert.match(source, /\["AWAITING_LOCAL_APPROVAL", "WAITING_LOCAL_APPROVAL"\]\.includes\(request\.status\)/);
});

test("local rejection remains an explicit non-execution decision", async () => {
  let requestedBody;
  const client = createApiClient({
    baseUrl: "http://local.invalid",
    fetchImpl: async (_url, options) => {
      requestedBody = JSON.parse(options.body);
      return new Response(JSON.stringify({ status: "REJECTED" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  await client.approveRemoteJob("central-1", { approved: false, ata_password: null });
  assert.deepEqual(requestedBody, { approved: false, ata_password: null });
  const source = readFileSync(new URL("../app/page.js", import.meta.url), "utf8");
  assert.match(source, /rejectRemoteRequest/);
  assert.match(source, /approved: false/);
});

test("central job detail uses the dedicated canonical central-job endpoint", async () => {
  let requestedUrl;
  const client = createApiClient({
    baseUrl: "https://central.example",
    fetchImpl: async (url) => {
      requestedUrl = url;
      return new Response(JSON.stringify({ central_job_id: "central/job" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });
  await client.getCentralJob("central/job");
  assert.equal(requestedUrl, "https://central.example/central-jobs/central%2Fjob");
});

test("central selected-job snapshots advance progressively and stop polling at terminal state", () => {
  const profiling = normalizeCentralJob({
    central_job_id: "central-1", status: "RUNNING", updated_at: "2026-08-27T10:00:00Z",
    events: [{ sequence: 1, state: "STAGE_PROFILING_STARTED" }],
  });
  const policy = normalizeCentralJob({
    central_job_id: "central-1", status: "RUNNING", updated_at: "2026-08-27T10:00:01Z",
    events: [
      { sequence: 1, state: "STAGE_PROFILING_STARTED" },
      { sequence: 2, state: "STAGE_PROFILING_COMPLETED" },
      { sequence: 3, state: "STAGE_POLICY_STARTED" },
    ],
  });
  const terminal = normalizeCentralJob({
    central_job_id: "central-1", status: "VERIFIED", final_status: "VERIFIED",
    updated_at: "2026-08-27T10:00:02Z", events: policy.events,
  });

  let jobs = upsertCentralJob([], profiling);
  assert.equal(shouldPollCentralJob(jobs[0]), true);
  jobs = upsertCentralJob(jobs, policy);
  assert.deepEqual(pipelineStatuses(jobs[0].state_history_json.map((event) => event.state)), ["done", "current", "pending", "pending", "pending", "pending"]);
  assert.equal(preferCentralJobSnapshot(policy, profiling), policy);
  jobs = upsertCentralJob(jobs, terminal);
  assert.equal(shouldPollCentralJob(jobs[0]), false);
  assert.equal(shouldPollCentralJob(normalizeCentralJob({
    central_job_id: "central-rejected", status: "REJECTED", final_status: "REJECTED",
  })), false);

  const listSnapshot = mergeCentralJobList(jobs, [profiling]);
  assert.equal(listSnapshot[0].final_status, "VERIFIED");

  const source = readFileSync(new URL("../app/page.js", import.meta.url), "utf8");
  assert.match(source, /window\.setInterval\(poll, 1000\)/);
  assert.match(source, /const created = normalizeCentralJob\(await apiClient\.createCentralJob/);
  assert.match(source, /setSelectedJobId\(created\.id\)/);
  assert.doesNotMatch(source, /await apiClient\.createCentralJob[\s\S]{0,800}await refreshDashboardData/);
  assert.doesNotMatch(source, /navigator\.(?:platform|userAgent)/);
});

test("local export uses Tauri-compatible assets without changing central defaults", () => {
  const config = readFileSync(new URL("../next.config.mjs", import.meta.url), "utf8");
  const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  assert.match(config, /NEXT_PUBLIC_VYPER_MODE === "local"/);
  assert.match(config, /assetPrefix: localEmbeddedExport \? "\.\." : undefined/);
  assert.match(packageJson.scripts["build:local"], /NEXT_PUBLIC_VYPER_MODE=local/);

  for (const base of [
    "tauri://localhost/",
    "tauri://localhost/download/",
    "http://127.0.0.1:8787/",
    "http://127.0.0.1:8787/download/",
  ]) {
    assert.equal(new URL("../_next/static/chunks/app.css", base).pathname, "/_next/static/chunks/app.css");
    assert.equal(new URL("../_next/static/chunks/app.js", base).pathname, "/_next/static/chunks/app.js");
  }
});

test("dashboard structural styles are bundled for Tauri CSP processing", () => {
  const dashboardSource = readFileSync(new URL("../app/page.js", import.meta.url), "utf8");
  const globalStyles = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
  const tauriConfig = JSON.parse(readFileSync(
    new URL("../src-tauri/tauri.conf.json", import.meta.url),
    "utf8",
  ));

  assert.doesNotMatch(dashboardSource, /<style>\{`[\s\S]*?\.nb-root/);
  assert.match(globalStyles, /\.nb-root\s*\{/);
  assert.match(globalStyles, /\.nb-shell\s*\{/);
  assert.equal(tauriConfig.app.security.dangerousDisableAssetCspModification, undefined);
  assert.match(tauriConfig.app.security.csp, /style-src 'self' 'unsafe-inline'/);
});

test("dashboard downloads use the central Linux artifact contract without leaving the shell", () => {
  const releases = [
    { platform: "windows", architecture: "x86_64", download_url: "/downloads/windows.zip" },
    { platform: "linux", architecture: "x86_64", download_url: "/downloads/vyper.tar.gz", sha256: "b".repeat(64) },
  ];
  const release = selectLinuxX64Release(releases);
  assert.equal(release, releases[1]);
  assert.equal(releaseDownloadUrl("https://central.example", release), "https://central.example/downloads/vyper.tar.gz");

  const dashboardSource = readFileSync(new URL("../app/page.js", import.meta.url), "utf8");
  assert.match(dashboardSource, /id: "downloads", label: "Downloads"/);
  assert.doesNotMatch(dashboardSource, /label: "Downloads"[^\n]*href:/);
  assert.match(dashboardSource, /screen === "downloads" && !localMode && dashboardAccessReady/);
  assert.match(dashboardSource, /apiClient\.listDownloads\(\)/);
  assert.match(dashboardSource, /<DownloadsContent apiBase=\{apiUrl\}/);

  const directPageSource = readFileSync(new URL("../app/download/page.js", import.meta.url), "utf8");
  assert.match(directPageSource, /client\.listDownloads\(\)/);
  assert.match(directPageSource, /<DownloadsContent/);
});

test("FastAPI validation details retain HTTP status and safe field messages", () => {
  const error = new ApiError(
    "body.authorization: Field required",
    422,
    [{ loc: ["body", "authorization"], msg: "Field required" }],
  );
  assert.equal(formatApiError(error), "HTTP 422: body.authorization: Field required");
});
