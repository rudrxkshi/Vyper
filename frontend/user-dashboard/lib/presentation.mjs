export const JOB_STATE_META = {
  PENDING: { stage: -1, tone: "pend", label: "Pending" },
  PROFILING: { stage: 0, tone: "acc", label: "Profiling" },
  POLICY_SELECTED: { stage: 1, tone: "acc", label: "Policy selected" },
  AWAITING_AUTHORIZATION: { stage: 1, tone: "warn", label: "Awaiting authorization" },
  RUNNING: { stage: 2, tone: "acc", label: "Running" },
  VERIFYING: { stage: 3, tone: "acc", label: "Verifying" },
  VERIFIED: { stage: 5, tone: "ok", label: "Verified", successful: true },
  FAILED: { stage: 2, tone: "bad", label: "Failed" },
  INCONCLUSIVE: { stage: 3, tone: "warn", label: "Inconclusive" },
  UNSUPPORTED: { stage: 0, tone: "bad", label: "Unsupported" },
  CANCELLED: { stage: -1, tone: "pend", label: "Cancelled" },
};

const FINAL_STATUS_META = {
  VERIFIED: { tone: "ok", label: "Verified", successful: true },
  FAILED: { tone: "bad", label: "Failed", successful: false },
  INCONCLUSIVE: { tone: "warn", label: "Inconclusive", successful: false },
  UNSUPPORTED: { tone: "bad", label: "Unsupported", successful: false },
  CANCELLED: { tone: "pend", label: "Cancelled", successful: false },
  PENDING: { tone: "pend", label: "Pending", successful: false },
  PROFILING: { tone: "acc", label: "Profiling", successful: false },
  POLICY_SELECTED: { tone: "acc", label: "Policy selected", successful: false },
  AWAITING_AUTHORIZATION: { tone: "warn", label: "Awaiting authorization", successful: false },
  RUNNING: { tone: "acc", label: "Running", successful: false },
  VERIFYING: { tone: "acc", label: "Verifying", successful: false },
};

export function normalizeText(value) {
  return String(value ?? "").toLowerCase();
}

export function getJobStateMeta(status) {
  return JOB_STATE_META[status] || {
    stage: -1,
    tone: "pend",
    label: String(status || "Unknown"),
  };
}

export function getFinalStatusMeta(status) {
  if (!status) return { tone: "pend", label: "—", successful: false };
  return FINAL_STATUS_META[status] || {
    tone: "pend",
    label: String(status),
    successful: false,
  };
}

export function getOutcomePresentation(certificate) {
  const finalStatus = certificate?.final_status;
  const successful =
    finalStatus === "VERIFIED" &&
    certificate?.successful_sanitization_claim === true &&
    certificate?.outcome_kind === "sanitization_certificate";

  if (successful) {
    return { title: "Sanitization certificate", detail: "Verification succeeded", tone: "ok" };
  }

  const detail = {
    FAILED: "Verification failed",
    INCONCLUSIVE: "Verification inconclusive",
    UNSUPPORTED: "Sanitization unsupported",
    CANCELLED: "Operation cancelled",
  }[finalStatus] || "No successful sanitization claim";

  return {
    title: certificate?.outcome_kind === "outcome_report" ? "Outcome report" : "Sanitization outcome",
    detail,
    tone: getFinalStatusMeta(finalStatus).tone,
  };
}

export function certificateView(certificate) {
  return {
    certificateId: certificate?.certificate_id ?? "—",
    certificateHash: certificate?.certificate_hash ?? "—",
    successfulClaim: certificate?.successful_sanitization_claim === true,
    outcomeKind: certificate?.outcome_kind ?? "—",
    certificateJson: certificate?.certificate_json ?? {},
    ...getOutcomePresentation(certificate),
  };
}

export function auditLogView(log) {
  return {
    action: log?.action ?? "—",
    actor: log?.actor ?? "—",
    target: log?.target ?? log?.request_json?.target ?? "—",
    requestJson: log?.request_json ?? {},
    responseJson: log?.response_json ?? {},
    createdAt: log?.created_at ?? "—",
  };
}

export function filterAssets(assets, { assetType = "All", assetMount = "All", search = "" } = {}) {
  const query = normalizeText(search);
  return (assets || []).filter((asset) => {
    if (assetType !== "All" && asset?.device_type !== assetType) return false;
    if (assetMount === "Mounted" && !asset?.mounted) return false;
    if (assetMount === "Unmounted" && asset?.mounted) return false;
    if (!query) return true;
    return [asset?.model, asset?.serial_number, asset?.target, asset?.device_type]
      .some((value) => normalizeText(value).includes(query));
  });
}

export function filterAuditLogs(logs, { actor = "", action = "All" } = {}) {
  const actorQuery = normalizeText(actor);
  return (logs || []).filter((log) => {
    if (action !== "All" && log?.action !== action) return false;
    return !actorQuery || normalizeText(log?.actor).includes(actorQuery);
  });
}

export function formatBytes(value) {
  const bytes = Number(value);
  if (!Number.isFinite(bytes) || bytes < 0) return "Unknown size";
  if (bytes < 1024) return `${bytes} B`;
  const units = ["KiB", "MiB", "GiB", "TiB", "PiB"];
  let amount = bytes;
  let unit = "B";
  for (const candidate of units) {
    amount /= 1024;
    unit = candidate;
    if (amount < 1024) break;
  }
  return `${amount.toFixed(amount >= 10 ? 1 : 2)} ${unit}`;
}

export function normalizeDiscoveredDevices(devices) {
  return (devices || []).map((device) => ({
    ...device,
    id: device.device_path,
    asset_type: "storage",
    profile_json: {
      device_path: device.device_path,
      device_type: device.device_type,
      capabilities: device.capabilities || {},
      warnings: device.warnings || [],
      profile_error: device.profile_error || null,
    },
  }));
}

export function normalizeLocalJob(job) {
  const certificatePayload = job?.certificate || {};
  const certificate = Object.keys(certificatePayload).length
    ? {
        ...certificatePayload,
        id: certificatePayload.certificate_id || `${job.local_job_id}-outcome`,
        job_id: job.local_job_id,
        certificate_json: certificatePayload,
      }
    : null;
  return {
    id: job?.local_job_id,
    local_job_id: job?.local_job_id,
    target: job?.target ?? "",
    dry_run: Boolean(job?.dry_run ?? job?.execution?.dry_run),
    job_state: job?.job_state ?? "PENDING",
    final_status: job?.final_status ?? null,
    pathway: job?.policy?.selected_pathway ?? null,
    outcome_kind: certificatePayload.outcome_kind ?? null,
    successful_sanitization_claim: certificatePayload.successful_sanitization_claim === true,
    message: job?.message ?? "",
    state_history_json: job?.state_history || [],
    progress: job?.progress ?? null,
    error_json: job?.error ?? null,
    created_at: job?.created_at ?? null,
    updated_at: job?.updated_at ?? null,
    started_at: job?.started_at ?? null,
    finished_at: job?.finished_at ?? null,
    profile_json: job?.profile || {},
    policy_json: job?.policy || {},
    execution_json: job?.execution || {},
    verification_json: job?.verification || {},
    evidence_json: job?.evidence || {},
    certificate_json: certificatePayload,
    certificate,
    audit_logs: [],
  };
}

export function getProgressPresentation(progress) {
  if (
    progress?.kind === "bytes" &&
    Number.isFinite(progress.bytes_completed) &&
    Number.isFinite(progress.bytes_total) &&
    progress.bytes_completed >= 0 &&
    progress.bytes_total > 0
  ) {
    const percentage = Math.min(100, Math.max(0, (progress.bytes_completed / progress.bytes_total) * 100));
    return {
      kind: "bytes",
      percentage,
      label: `${formatBytes(progress.bytes_completed)} of ${formatBytes(progress.bytes_total)}`,
    };
  }
  return {
    kind: "indeterminate",
    percentage: null,
    label: "Operation in progress; this pathway does not expose trustworthy numeric progress.",
  };
}

export function shouldPollLocalJob(job) {
  return Boolean(job?.id) && !["VERIFIED", "FAILED", "INCONCLUSIVE", "UNSUPPORTED", "CANCELLED"].includes(job.job_state);
}

export function normalizeRemoteAgent(agent) {
  return {
    ...agent,
    id: agent?.agent_id,
    online: agent?.status === "ONLINE",
    asset_count: Number(agent?.asset_count || 0),
    active_jobs: Number(agent?.active_jobs || 0),
    verified_jobs: Number(agent?.verified_jobs || 0),
  };
}

export function normalizeCentralJob(job) {
  const result = job?.result || {};
  return {
    ...job,
    id: job?.central_job_id,
    target: job?.requested_target,
    job_state: job?.local_execution_state || job?.status || "QUEUED",
    final_status: job?.final_status ?? null,
    progress: job?.progress ?? null,
    dry_run: Boolean(job?.dry_run ?? job?.request?.dry_run),
    execution_json: result.execution ?? null,
    verification_json: result.verification ?? null,
    evidence_json: result.evidence ?? null,
    state_history_json: result.state_history || job?.events || [],
    error_json: result.error ?? null,
    certificate: result.certificate ?? null,
    waiting_local_approval: job?.status === "WAITING_LOCAL_APPROVAL",
    execution_mode: job?.execution_mode || job?.request?.execution_mode || "normal_local",
    boot_lifecycle: (job?.execution_mode || job?.request?.execution_mode) === "boot_sanitize"
      ? (job?.boot_lifecycle || job?.local_execution_state || job?.status || "PREPARING_BOOT")
      : null,
  };
}

export function auditLogsForJob(job, auditLogs = []) {
  if (!job) return [];
  if (job.central_job_id) {
    const resource = `central-job:${job.central_job_id}`;
    return auditLogs.filter((entry) => entry?.resource === resource);
  }
  const matched = auditLogs.filter((entry) => entry?.job_id === job.id);
  return matched.length ? matched : (Array.isArray(job.audit_logs) ? job.audit_logs : []);
}

export function remoteAssetsForJob(assets = [], { dryRun = true, executionMode = "normal_local" } = {}) {
  if (dryRun || executionMode !== "normal_local") return assets;
  return assets.filter((asset) => {
    const profile = asset?.profile_json || {};
    return profile.is_system_device !== true
      && profile.mounted === false
      && profile.eligible_for_sanitization === true;
  });
}

export function getDeviceProtection(device) {
  if (!device) return { blocked: true, reason: "No device selected.", warning: null };
  if (device.profile_error || device.is_system_device == null) {
    return {
      blocked: true,
      reason: device.profile_error || "System-device status is unknown.",
      warning: "Unknown safety state must not be treated as safe.",
    };
  }
  if (device.is_system_device) {
    return {
      blocked: true,
      reason: "This is the system disk and cannot be wiped from the currently running operating system.",
      warning: null,
    };
  }
  if (device.eligible_for_sanitization === false) {
    return {
      blocked: true,
      reason: "Device discovery did not establish this device as an eligible sanitization target.",
      warning: "Unknown or unsupported device state must not be treated as safe.",
    };
  }
  if (device.mounted) {
    return {
      blocked: false,
      reason: null,
      warning: "This device has mounted filesystems. VYPER will not auto-unmount them.",
    };
  }
  return { blocked: false, reason: null, warning: null };
}

export function mountedPartitionsText(partitions) {
  return (partitions || [])
    .map((entry) => {
      if (typeof entry === "string") return entry;
      const path = entry?.path || "unknown device";
      return entry?.mountpoint ? `${path} at ${entry.mountpoint}` : path;
    })
    .join(", ");
}
