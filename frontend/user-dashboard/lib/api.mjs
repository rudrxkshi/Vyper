const DEVELOPMENT_API_BASE_URL = "http://127.0.0.1:8000";
const DEVELOPMENT_LOCAL_AGENT_BASE_URL = "http://127.0.0.1:8765";

export const API_URL_STORAGE_KEY = "vyper.apiBaseUrl";
export const LOCAL_API_URL_STORAGE_KEY = "vyper.localAgentApiBaseUrl";
export const API_KEY_STORAGE_KEY = "vyper.apiKey";
export const LOCAL_JOB_ID_STORAGE_KEY = "vyper.localJobId";

export class ApiError extends Error {
  constructor(message, status, detail = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

export function normalizeApiBaseUrl(value) {
  const normalized = String(value ?? "").trim().replace(/\/+$/, "");
  return normalized || DEVELOPMENT_API_BASE_URL;
}

export function getDefaultApiBaseUrl() {
  if (getDashboardMode() === "local") {
    return normalizeApiBaseUrl(
      process.env.NEXT_PUBLIC_VYPER_LOCAL_AGENT_API_BASE_URL ||
        process.env.NEXT_PUBLIC_VYPER_API_BASE_URL ||
        DEVELOPMENT_LOCAL_AGENT_BASE_URL,
    );
  }
  return normalizeApiBaseUrl(
    process.env.NEXT_PUBLIC_VYPER_API_BASE_URL || DEVELOPMENT_API_BASE_URL,
  );
}

export function getDashboardMode() {
  return String(process.env.NEXT_PUBLIC_VYPER_MODE || "central").toLowerCase() === "local"
    ? "local"
    : "central";
}

export function buildSanitizeRequest(form) {
  const approved = Boolean(form?.authorized);
  const password = approved ? String(form?.ataPassword ?? "").trim() : "";
  return {
    target: String(form?.target ?? ""),
    authorization: {
      approved,
      ata_password: password || null,
    },
    dry_run: Boolean(form?.dryRun),
  };
}

function describeDetail(detail) {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        const location = Array.isArray(item?.loc) ? item.loc.join(".") : "request";
        return `${location}: ${item?.msg || "Invalid value"}`;
      })
      .join("; ");
  }
  if (detail && typeof detail === "object") return JSON.stringify(detail);
  return "Request failed";
}

export function formatApiError(error) {
  if (error instanceof ApiError) {
    return `HTTP ${error.status}: ${error.message}`;
  }
  return error instanceof Error ? error.message : "Request failed";
}

export function loadApiSettings(storage) {
  if (!storage) return { apiUrl: getDefaultApiBaseUrl(), apiKey: "" };
  const apiUrlStorageKey = getDashboardMode() === "local"
    ? LOCAL_API_URL_STORAGE_KEY
    : API_URL_STORAGE_KEY;
  return {
    apiUrl: normalizeApiBaseUrl(storage.getItem(apiUrlStorageKey) || getDefaultApiBaseUrl()),
    apiKey: getDashboardMode() === "local" ? storage.getItem(API_KEY_STORAGE_KEY) || "" : "",
  };
}

export function saveApiSettings(storage, { apiUrl, apiKey }) {
  if (!storage) return;
  const apiUrlStorageKey = getDashboardMode() === "local"
    ? LOCAL_API_URL_STORAGE_KEY
    : API_URL_STORAGE_KEY;
  storage.setItem(apiUrlStorageKey, normalizeApiBaseUrl(apiUrl));
  if (getDashboardMode() === "local" && apiKey) storage.setItem(API_KEY_STORAGE_KEY, apiKey);
  else storage.removeItem(API_KEY_STORAGE_KEY);
}

export function clearApiSettings(storage) {
  if (!storage) return;
  const apiUrlStorageKey = getDashboardMode() === "local"
    ? LOCAL_API_URL_STORAGE_KEY
    : API_URL_STORAGE_KEY;
  storage.removeItem(apiUrlStorageKey);
  storage.removeItem(API_KEY_STORAGE_KEY);
}

export function loadLocalJobId(storage) {
  return storage?.getItem(LOCAL_JOB_ID_STORAGE_KEY) || null;
}

export function saveLocalJobId(storage, localJobId) {
  if (!storage) return;
  if (localJobId) storage.setItem(LOCAL_JOB_ID_STORAGE_KEY, localJobId);
  else storage.removeItem(LOCAL_JOB_ID_STORAGE_KEY);
}

export function readCookie(name, cookieString = globalThis.document?.cookie || "") {
  const prefix = `${encodeURIComponent(name)}=`;
  const match = String(cookieString).split(";").map((item) => item.trim()).find((item) => item.startsWith(prefix));
  return match ? decodeURIComponent(match.slice(prefix.length)) : "";
}

export function createApiClient({
  baseUrl,
  apiKey = "",
  expectedService = null,
  fetchImpl = globalThis.fetch,
}) {
  const normalizedBaseUrl = normalizeApiBaseUrl(baseUrl);
  let csrfToken = readCookie("vyper_csrf");

  async function request(path, options = {}) {
    const headers = new Headers(options.headers || {});
    if (apiKey) headers.set("X-VYPER-API-Key", apiKey);
    if (options.body && !headers.has("Content-Type")) {
      headers.set("Content-Type", "application/json");
    }
    if (csrfToken && ["POST", "PUT", "PATCH", "DELETE"].includes(String(options.method || "GET").toUpperCase())) {
      headers.set("X-CSRF-Token", csrfToken);
    }

    const response = await fetchImpl(`${normalizedBaseUrl}${path}`, {
      credentials: "include",
      ...options,
      headers,
    });
    const contentType = response.headers.get("content-type") || "";
    let body = null;
    if (contentType.includes("application/json")) {
      body = await response.json();
    } else {
      const text = await response.text();
      body = text || null;
    }

    if (!response.ok) {
      const detail = body && typeof body === "object" ? body.detail : body;
      throw new ApiError(describeDetail(detail), response.status, detail);
    }
    if (body?.csrf_token) csrfToken = body.csrf_token;
    return body;
  }

  return {
    health: async () => {
      const body = await request("/health");
      return body?.status === "ok" && (!expectedService || body?.service === expectedService);
    },
    login: (username, password) => request("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
    logout: () => request("/auth/logout", { method: "POST" }),
    changePassword: (password) => request("/auth/debug/password", { method: "POST", body: JSON.stringify({ password }) }),
    enrollMfa: (password) => request("/auth/mfa/enroll", { method: "POST", body: JSON.stringify({ password }) }),
    confirmMfa: (code) => request("/auth/mfa/confirm", { method: "POST", body: JSON.stringify({ code }) }),
    verifyMfa: (code) => request("/auth/mfa/verify", { method: "POST", body: JSON.stringify({ code }) }),
    currentUser: () => request("/auth/me"),
    listAssets: () => request("/assets"),
    listDevices: () => request("/devices"),
    listJobs: () => request("/jobs"),
    getJob: (jobId) => request(`/jobs/${encodeURIComponent(jobId)}`),
    listCertificates: () => request("/certificates"),
    listAuditLogs: () => request("/audit-logs"),
    listAgents: () => request("/agents"),
    listOrganizations: () => request("/organizations"),
    listPolicies: (organizationId) => request(`/organizations/${encodeURIComponent(organizationId)}/policies`),
    listSecurityEvents: () => request("/security-events"),
    listAgentAssets: (agentId) => request(`/agents/${encodeURIComponent(agentId)}/assets`),
    listCentralJobs: () => request("/central-jobs"),
    getCentralJob: (centralJobId) => request(`/central-jobs/${encodeURIComponent(centralJobId)}`),
    listDownloads: () => request("/downloads"),
    listRemoteJobs: () => request("/remote-jobs"),
    getSyncStatus: () => request("/sync/status"),
    approveRemoteJob: (centralJobId, payload) => request(
      `/remote-jobs/${encodeURIComponent(centralJobId)}/approve`,
      {
        method: "POST",
        body: JSON.stringify(payload),
      },
    ),
    createCentralJob: (agentId, payload) => request(`/agents/${encodeURIComponent(agentId)}/jobs`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
    decideCentralJob: (centralJobId, decision) => request(
      `/central-jobs/${encodeURIComponent(centralJobId)}/approvals`,
      { method: "POST", body: JSON.stringify({ decision }) },
    ),
    createSanitizeJob: (form) =>
      request("/jobs/sanitize", {
        method: "POST",
        body: JSON.stringify(buildSanitizeRequest(form)),
      }),
  };
}

export async function checkBackendConnection(client) {
  try {
    return (await client.health()) === true;
  } catch {
    return false;
  }
}
