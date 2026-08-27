"use client";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  LayoutGrid, HardDrive, ListChecks, FileCheck2, ScrollText, Settings as SettingsIcon,
  ChevronDown, ShieldCheck, Lock, Search, X, Check, TriangleAlert, CircleDot, Users,
  Download as DownloadIcon, ShieldAlert, BookOpenCheck,
} from "lucide-react";
import {
  checkBackendConnection,
  clearApiSettings,
  createApiClient,
  formatApiError,
  getDefaultApiBaseUrl,
  getDashboardMode,
  loadApiSettings,
  loadLocalJobId,
  saveApiSettings,
  saveLocalJobId,
} from "../lib/api.mjs";

import {
  JOB_STATE_META,
  auditLogView,
  auditLogsForJob,
  certificateView,
  filterAssets,
  filterAuditLogs,
  formatBytes,
  getDeviceProtection,
  getFinalStatusMeta,
  getJobStateMeta,
  getProgressPresentation,
  mountedPartitionsText,
  normalizeDiscoveredDevices,
  normalizeCentralJob,
  normalizeLocalJob,
  normalizeRemoteAgent,
  remoteAssetsForJob,
  shouldPollLocalJob,
} from "../lib/presentation.mjs";
import { loadLocalConsoleData } from "../lib/local-console-data.mjs";
import { selectLinuxX64Release } from "../lib/downloads.mjs";
import DownloadsContent from "./downloads-content";

const PRODUCT_VERSION = "1.0.0-rc1";
const STAGES = ["Profiling", "Policy", "Execution", "Verification", "Evidence", "Certificate"];
const TERMINAL_JOB_STATES = new Set(["VERIFIED", "FAILED", "INCONCLUSIVE", "UNSUPPORTED", "CANCELLED"]);

function newDashboardIdempotencyKey() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  const values = globalThis.crypto.getRandomValues(new Uint32Array(4));
  return `dashboard-${Array.from(values, (value) => value.toString(16).padStart(8, "0")).join("")}`;
}

function Badge({ tone = "pend", children, stamp }) {
  return (
    <span className={"nb-badge nb-tone-" + tone + (stamp ? " nb-stamp" : "")}>
      {children}
    </span>
  );
}
function JsonPanel({ title, json, defaultOpen }) {
  const [open, setOpen] = useState(!!defaultOpen);

  const displayJson =
    typeof json === "string"
      ? json
      : JSON.stringify(json ?? {}, null, 2);

  return (
    <div className={"nb-json" + (open ? " open" : "")}>
      <button
        className="nb-json-head"
        onClick={() => setOpen(!open)}
        aria-expanded={open}
      >
        <span>{title}</span>
        <ChevronDown size={16} className="nb-chev" />
      </button>

      {open && (
        <pre className="nb-json-body">
          {displayJson}
        </pre>
      )}
    </div>
  );
}
function Pipeline({ jobState }) {
  const meta = getJobStateMeta(jobState);
  const failedAt = jobState === "FAILED" || jobState === "UNSUPPORTED" ? meta.stage : -1;
  return (
    <div className="nb-pipeline">
      {STAGES.map((label, i) => {
        let cls = "pend";
        if (failedAt === i) cls = "bad";
        else if (i < meta.stage || meta.successful) cls = "done";
        else if (i === meta.stage) cls = "current";
        return (
          <div className={"nb-pstep nb-pstep-" + cls} key={label}>
            <div className="nb-pstep-line" />
            <div className="nb-pstep-circle">
              {cls === "done" ? <Check size={14} /> : cls === "bad" ? <X size={14} /> : i + 1}
            </div>
            <div className="nb-pstep-label">{label}</div>
          </div>
        );
      })}
    </div>
  );
}

export default function VyperDashboard() {
  const localMode = getDashboardMode() === "local";
  const [screen, setScreen] = useState(() =>
    localMode && typeof window !== "undefined" && loadLocalJobId(window.localStorage)
      ? "jobdetail"
      : "dashboard",
  );
  const [assets, setAssets] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [certs, setCerts] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [remoteAgents, setRemoteAgents] = useState([]);
  const [remoteAssets, setRemoteAssets] = useState([]);
  const [centralJobs, setCentralJobs] = useState([]);
  const [organizations, setOrganizations] = useState([]);
  const [remotePolicies, setRemotePolicies] = useState([]);
  const [securityEvents, setSecurityEvents] = useState([]);
  const [downloadRelease, setDownloadRelease] = useState(null);
  const [downloadError, setDownloadError] = useState("");
  const [remoteRequests, setRemoteRequests] = useState([]);
  const [syncStatus, setSyncStatus] = useState(null);
  const [remoteApprovalPassword, setRemoteApprovalPassword] = useState("");
  const [remoteApprovalError, setRemoteApprovalError] = useState("");
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [remoteJobForm, setRemoteJobForm] = useState({ assetId: "", policyId: "", dryRun: true, authorized: false, executionMode: "normal_local" });
  const [remoteJobError, setRemoteJobError] = useState("");

  const [loading, setLoading] = useState(true);
  const [backendConnected, setBackendConnected] = useState(false);
  const [dataError, setDataError] = useState("");

  const [selectedAssetId, setSelectedAssetId] = useState(null);
  const [selectedJobId, setSelectedJobId] = useState(() =>
    typeof window === "undefined" ? null : loadLocalJobId(window.localStorage),
  );
  const [selectedCertId, setSelectedCertId] = useState(null);

  const [assetType, setAssetType] = useState("All");
  const [assetMount, setAssetMount] = useState("All");
  const [assetSearch, setAssetSearch] = useState("");

  const [jobStateFilter, setJobStateFilter] = useState("All");

  const [auditActor, setAuditActor] = useState("");
  const [auditAction, setAuditAction] = useState("All");

  const [form, setForm] = useState({ target: "", ataPassword: "", dryRun: true, authorized: false });
  const [formError, setFormError] = useState("");

  const [apiUrl, setApiUrl] = useState(() =>
    loadApiSettings(typeof window === "undefined" ? null : window.localStorage).apiUrl,
  );
  const [apiKey, setApiKey] = useState(() =>
    loadApiSettings(typeof window === "undefined" ? null : window.localStorage).apiKey,
  );
  const [savedMsg, setSavedMsg] = useState("");
  const [operatorUser, setOperatorUser] = useState(localMode ? { role: "LOCAL" } : undefined);
  const [loginForm, setLoginForm] = useState({ username: "", password: "" });
  const [loginError, setLoginError] = useState("");
  const [mfaRequired, setMfaRequired] = useState(false);
  const [mfaCode, setMfaCode] = useState("");
  const [debugPassword, setDebugPassword] = useState("");
  const [debugPasswordMsg, setDebugPasswordMsg] = useState("");

  const apiClient = useMemo(
    () => createApiClient({
      baseUrl: apiUrl,
      apiKey,
      expectedService: localMode ? "local-agent" : "central",
    }),
    [apiUrl, apiKey, localMode],
  );

  const refreshDashboardData = useCallback(async ({ showLoading = false } = {}) => {
    if (showLoading) setLoading(true);
    setDataError("");

    const connected = await checkBackendConnection(apiClient);
    setBackendConnected(connected);
    if (!connected) {
      setDataError("Unable to reach the VYPER API health endpoint.");
      if (showLoading) setLoading(false);
      return false;
    }

    if (!localMode) {
      try {
        const currentUser = await apiClient.currentUser();
        setOperatorUser(currentUser);
        setMfaRequired(Boolean(currentUser.mfa_required));
      } catch (error) {
        if (error?.status === 401) {
          setOperatorUser(null);
          setDataError("");
          if (showLoading) setLoading(false);
          return false;
        }
        setDataError(formatApiError(error));
        if (showLoading) setLoading(false);
        return false;
      }
    }

    try {
      let assetsData;
      if (localMode) {
        const localData = await loadLocalConsoleData(apiClient);
        assetsData = normalizeDiscoveredDevices(localData.devices);
        setRemoteRequests(localData.remoteRequests);
        setSyncStatus(localData.syncStatus);
        setCerts(localData.certificates);
        setSelectedCertId((current) =>
          localData.certificates.some((certificate) => certificate.id === current)
            ? current
            : localData.certificates[0]?.id || null,
        );
        setAuditLogs(localData.auditLogs);
        const normalizedJobs = localData.jobs.map(normalizeLocalJob);
        setJobs(normalizedJobs);
        setSelectedJobId((current) =>
          normalizedJobs.some((job) => job.id === current) ? current : normalizedJobs[0]?.id || null,
        );
      } else {
        const [persistedAssets, jobsData, certsData, auditData, agentsData, centralJobsData, organizationsData, securityEventsData] = await Promise.all([
          apiClient.listAssets(),
          apiClient.listJobs(),
          apiClient.listCertificates(),
          apiClient.listAuditLogs(),
          apiClient.listAgents(),
          apiClient.listCentralJobs(),
          apiClient.listOrganizations(),
          apiClient.listSecurityEvents(),
        ]);
        const policiesData = (await Promise.all(
          organizationsData.map((organization) => apiClient.listPolicies(organization.id)),
        )).flat();
        assetsData = persistedAssets;
        const normalizedCentralJobs = centralJobsData.map(normalizeCentralJob);
        const allJobs = [...jobsData, ...normalizedCentralJobs];
        setJobs(allJobs);
        setSelectedJobId((current) =>
          allJobs.some((job) => job.id === current) ? current : allJobs[0]?.id || null,
        );
        setCerts(certsData);
        setSelectedCertId((current) =>
          certsData.some((certificate) => certificate.id === current)
            ? current
            : certsData[0]?.id || null,
        );
        setAuditLogs(auditData);
        const normalizedAgents = agentsData.map(normalizeRemoteAgent);
        setRemoteAgents(normalizedAgents);
        setCentralJobs(normalizedCentralJobs);
        setOrganizations(organizationsData);
        setRemotePolicies(policiesData);
        setSecurityEvents(securityEventsData);
        setSelectedAgentId((current) => current || normalizedAgents[0]?.agent_id || "");
      }

      setAssets(assetsData);
      setSelectedAssetId((current) =>
        assetsData.some((asset) => asset.id === current) ? current : assetsData[0]?.id || null,
      );
      setForm((current) => {
        if (current.target) return current;
        const firstValidAsset = assetsData.find((asset) => !getDeviceProtection(asset).blocked);
        return firstValidAsset ? { ...current, target: firstValidAsset.device_path } : current;
      });

      return true;
    } catch (error) {
      setDataError(formatApiError(error));
      return false;
    } finally {
      if (showLoading) setLoading(false);
    }
  }, [apiClient, localMode]);

  useEffect(() => {
    if (localMode || !selectedAgentId) return undefined;
    let cancelled = false;
    apiClient.listAgentAssets(selectedAgentId)
      .then((items) => {
        if (cancelled) return;
        setRemoteAssets(items);
        setRemoteJobForm((current) => ({ ...current, assetId: items.some((item) => item.id === current.assetId) ? current.assetId : items[0]?.id || "" }));
      })
      .catch((error) => !cancelled && setDataError(formatApiError(error)));
    return () => { cancelled = true; };
  }, [apiClient, localMode, selectedAgentId]);

  useEffect(() => {
    const initialRefreshId = window.setTimeout(
      () => refreshDashboardData({ showLoading: true }),
      0,
    );
    const intervalId = window.setInterval(() => refreshDashboardData(), 8000);
    return () => {
      window.clearTimeout(initialRefreshId);
      window.clearInterval(intervalId);
    };
  }, [refreshDashboardData]);

  const loadJobDetail = useCallback(async (jobId) => {
    try {
      const responseData = await apiClient.getJob(jobId);
      const jobData = localMode ? normalizeLocalJob(responseData) : responseData;

      setJobs((prev) =>
        prev.map((job) =>
          job.id === jobId ? { ...job, ...jobData } : job,
        )
      );

      return jobData;
    } catch (error) {
      setDataError(formatApiError(error));
      return null;
    }
  }, [apiClient, localMode]);

  useEffect(() => {
    if (!localMode || screen !== "jobdetail" || !selectedJobId) return undefined;
    const selected = jobs.find((job) => job.id === selectedJobId);
    if (selected && !shouldPollLocalJob(selected)) return undefined;
    const pollId = window.setInterval(() => loadJobDetail(selectedJobId), 1000);
    return () => window.clearInterval(pollId);
  }, [jobs, loadJobDetail, localMode, screen, selectedJobId]);

  useEffect(() => {
    if (localMode || screen !== "downloads" || !operatorUser || mfaRequired) return undefined;
    let cancelled = false;
    apiClient.listDownloads()
      .then((items) => {
        if (!cancelled) {
          setDownloadError("");
          setDownloadRelease(selectLinuxX64Release(items));
        }
      })
      .catch((error) => {
        if (!cancelled) setDownloadError(formatApiError(error));
      });
    return () => { cancelled = true; };
  }, [apiClient, localMode, mfaRequired, operatorUser, screen]);

  function goto(screenId, opts) {
    setScreen(screenId);
    if (screenId === "downloads") setDownloadError("");

    if (opts?.jobId) {
      setSelectedJobId(opts.jobId);
      if (localMode) saveLocalJobId(window.localStorage, opts.jobId);

      if (screenId === "jobdetail") {
        loadJobDetail(opts.jobId);
      }
    }

    if (opts?.certId) {
      setSelectedCertId(opts.certId);
    }
  }

  async function submitJob(e) {
    e.preventDefault();

    if (!form.target) {
      setFormError("Choose a target device before submitting.");
      return;
    }

    if (!form.dryRun && !form.authorized) {
      setFormError(
        "Check the authorization box or enable dry run before submitting."
      );
      return;
    }
    const submittedDevice = assets.find((asset) => asset.device_path === form.target);
    const protection = getDeviceProtection(submittedDevice);
    if (!form.dryRun && protection.blocked) {
      setFormError(protection.reason || "This device cannot be selected for destructive execution.");
      return;
    }

    setFormError("");

    try {
      const responseData = await apiClient.createSanitizeJob(form);
      const newJob = localMode ? normalizeLocalJob(responseData) : responseData;
      if (localMode) {
        setJobs((current) => [newJob, ...current.filter((job) => job.id !== newJob.id)]);
        if (newJob.certificate) {
          setCerts((current) => [
            newJob.certificate,
            ...current.filter((certificate) => certificate.id !== newJob.certificate.id),
          ]);
        }
      }
      await refreshDashboardData();
      setSelectedJobId(newJob.id);

      goto("jobdetail", {
        jobId: newJob.id,
      });

      setForm({
        target: form.target,
        ataPassword: "",
        dryRun: form.dryRun,
        authorized: false,
      });

    } catch (error) {
      setFormError(formatApiError(error));
    }
  }
  
  const filteredAssets = filterAssets(assets, { assetType, assetMount, search: assetSearch });
  const selectedAsset = assets.find((a) => a.id === selectedAssetId) || null;
  const selectedTargetDevice = assets.find((a) => a.device_path === form.target) || null;
  const selectedTargetProtection = getDeviceProtection(selectedTargetDevice);

  const filteredJobs = jobs.filter((j) => jobStateFilter === "All" || j.job_state === jobStateFilter);
  const selectedJob = jobs.find((j) => j.id === selectedJobId) || null;
  const selectedJobProgress = getProgressPresentation(selectedJob?.progress);

  const selectedCert = certs.find((c) => c.id === selectedCertId) || null;
  const selectedCertView = selectedCert ? certificateView(selectedCert) : null;
  const selectedCertFinalMeta = selectedCert
    ? getFinalStatusMeta(selectedCert.final_status)
    : null;
  const selectedJobCertificateView = selectedJob?.certificate
    ? certificateView(selectedJob.certificate)
    : null;
  const selectedJobAuditLogs = auditLogsForJob(selectedJob, auditLogs);

  const filteredAuditLogs = filterAuditLogs(auditLogs, { actor: auditActor, action: auditAction });
  const selectableRemoteAssets = remoteAssetsForJob(remoteAssets, remoteJobForm);
  const selectedRemoteAssetIsSelectable = selectableRemoteAssets.some((asset) => asset.id === remoteJobForm.assetId);
  const selectedRemoteAgent = remoteAgents.find((agent) => agent.agent_id === selectedAgentId) || null;
  const selectedRemoteAsset = remoteAssets.find((asset) => asset.id === remoteJobForm.assetId) || null;
  const selectableRemotePolicies = remotePolicies.filter((policy) =>
    !policy.revoked_at && policy.organization_id === selectedRemoteAgent?.organization_id
  );
  const selectedRemotePolicy = selectableRemotePolicies.find((policy) => policy.id === remoteJobForm.policyId) || null;
  const counts = {
    total: assets.length,
    verified: jobs.filter((j) => getJobStateMeta(j.job_state).successful).length,
    failed: jobs.filter((j) => j.job_state === "FAILED").length,
    inconclusive: jobs.filter((j) => j.job_state === "INCONCLUSIVE").length,
  };

  async function submitRemoteJob(event) {
    event.preventDefault();
    if (!selectedAgentId || !remoteJobForm.assetId || !selectedRemoteAssetIsSelectable) {
      setRemoteJobError("Choose an enrolled agent and synchronized asset.");
      return;
    }
    if (!remoteJobForm.dryRun && !remoteJobForm.authorized) {
      setRemoteJobError("Central destructive authorization is required. Local approval will still be required separately.");
      return;
    }
    setRemoteJobError("");
    try {
      await apiClient.createCentralJob(selectedAgentId, {
        asset_id: remoteJobForm.assetId,
        dry_run: remoteJobForm.dryRun,
        central_authorized: remoteJobForm.authorized,
        destructive_confirmation: remoteJobForm.dryRun ? null : "SANITIZE",
        idempotency_key: newDashboardIdempotencyKey(),
        expires_in_seconds: 3600,
        execution_mode: remoteJobForm.executionMode,
        policy_id: selectedRemotePolicy?.id || null,
      });
      await refreshDashboardData();
    } catch (error) {
      setRemoteJobError(formatApiError(error));
    }
  }

  async function decideCentralJob(job, decision) {
    const consequence = decision === "APPROVED"
      ? `Approve destructive sanitization of ${job.requested_target}? This authorization cannot be treated as execution evidence and local approval is still required.`
      : `Reject sanitization of ${job.requested_target}?`;
    if (!window.confirm(consequence)) return;
    setRemoteJobError("");
    try {
      await apiClient.decideCentralJob(job.central_job_id, decision);
      await refreshDashboardData();
    } catch (error) {
      const message = formatApiError(error);
      if (/MFA-authenticated/i.test(message)) setMfaRequired(true);
      setRemoteJobError(message);
    }
  }

  async function approveRemoteRequest(centralJobId) {
    setRemoteApprovalError("");
    try {
      await apiClient.approveRemoteJob(centralJobId, {
        approved: true,
        ata_password: remoteApprovalPassword.trim() || null,
      });
      setRemoteApprovalPassword("");
      await refreshDashboardData();
    } catch (error) {
      setRemoteApprovalPassword("");
      setRemoteApprovalError(formatApiError(error));
    }
  }

  function persistSettings() {
    saveApiSettings(window.localStorage, { apiUrl, apiKey });
    setSavedMsg("Settings saved.");
    window.setTimeout(() => setSavedMsg(""), 2200);
  }

  function resetSettings() {
    clearApiSettings(window.localStorage);
    setApiUrl(getDefaultApiBaseUrl());
    setApiKey("");
    setSavedMsg("Settings cleared.");
    window.setTimeout(() => setSavedMsg(""), 2200);
  }

  async function changeDebugPassword() {
    setDebugPasswordMsg("");
    try {
      await apiClient.changePassword(debugPassword);
      setDebugPassword("");
      setDebugPasswordMsg("Changed.");
      window.setTimeout(() => setDebugPasswordMsg(""), 2200);
    } catch (error) {
      setDebugPasswordMsg(formatApiError(error));
    }
  }

  async function submitLogin(event) {
    event.preventDefault();
    setLoginError("");
    try {
      const user = await apiClient.login(loginForm.username, loginForm.password);
      setOperatorUser(user);
      setMfaRequired(Boolean(user.mfa_required));
      setLoginForm({ username: "", password: "" });
      if (!user.mfa_required) await refreshDashboardData({ showLoading: true });
    } catch (error) {
      setLoginForm((current) => ({ ...current, password: "" }));
      setLoginError(formatApiError(error));
    }
  }

  async function submitMfa(event) {
    event.preventDefault();
    setLoginError("");
    try {
      await apiClient.verifyMfa(mfaCode);
      const user = await apiClient.currentUser();
      setOperatorUser(user);
      setMfaRequired(false);
      setMfaCode("");
      await refreshDashboardData({ showLoading: true });
    } catch (error) {
      setMfaCode("");
      setLoginError(formatApiError(error));
    }
  }

  async function logoutOperator() {
    await apiClient.logout();
    setOperatorUser(null);
    setMfaRequired(false);
    setAssets([]); setJobs([]); setCerts([]); setAuditLogs([]); setRemoteAgents([]); setCentralJobs([]);
    setOrganizations([]); setRemotePolicies([]); setSecurityEvents([]);
  }
  const NAV = [
    { id: "dashboard", label: "Dashboard", icon: LayoutGrid },
    ...(!localMode ? [{ id: "agents", label: "Agents", icon: Users }] : []),
    ...(!localMode ? [{ id: "policies", label: "Policies", icon: BookOpenCheck }] : []),
    ...(!localMode ? [{ id: "security-events", label: "Security events", icon: ShieldAlert }] : []),
    ...(localMode ? [{ id: "remote-requests", label: "Remote requests", icon: ShieldCheck }] : []),
    ...(!localMode ? [{ id: "downloads", label: "Downloads", icon: DownloadIcon }] : []),
    { id: "assets", label: "Assets", icon: HardDrive },
    { id: "jobs", label: "Jobs", icon: ListChecks },
    { id: "certificates", label: "Certificates", icon: FileCheck2 },
    { id: "auditlogs", label: "Audit logs", icon: ScrollText },
    { id: "settings", label: "Settings", icon: SettingsIcon },
  ];
  const dashboardAccessReady = localMode || (operatorUser !== null && !mfaRequired);
  return (
    <div className="nb-root">
      <div className="nb-shell">
        <aside className="nb-sidebar">
          <div className="nb-brand">
            <div className="nb-brand-mark"><Lock size={16} /></div>
            <div className="nb-brand-name">VYPER</div>
            <div className="nb-brand-sub">Sanitization console</div>
          </div>
          <nav className="nb-nav">
            {NAV.map((n) => {
              const Icon = n.icon;
              return (
                <button key={n.id} className={"nb-nav-item" + (screen === n.id ? " active" : "")} onClick={() => goto(n.id)}>
                  <Icon size={16} aria-hidden="true" />
                  {n.label}
                </button>
              );
            })}
          </nav>
          <div className="nb-sidebar-footer">
            <span className="nb-dot" style={!backendConnected ? { background: "var(--bad-line)" } : {}} />
            {backendConnected ? "API connected" : "API disconnected"}
          </div>
          {!localMode && operatorUser ? <button className="nb-nav-item" type="button" onClick={logoutOperator}>
            Sign out ({operatorUser.role})
          </button> : null}
        </aside>
        <main className="nb-main">
          {!localMode && operatorUser === null && !mfaRequired ? <form className="nb-card" onSubmit={submitLogin}>
            <div className="nb-crumbs">Authenticated access</div>
            <h1 className="nb-h1 nb-heading">Sign in to VYPER</h1>
            <p className="nb-sub">Use a central operator account. Session credentials remain in a Secure, HttpOnly cookie.</p>
            <div className="nb-field"><label>Username</label><input type="text" autoComplete="username" required value={loginForm.username} onChange={(event) => setLoginForm({ ...loginForm, username: event.target.value })} /></div>
            <div className="nb-field"><label>Password</label><input type="password" autoComplete="current-password" required value={loginForm.password} onChange={(event) => setLoginForm({ ...loginForm, password: event.target.value })} /></div>
            {loginError ? <div className="nb-error">{loginError}</div> : null}
            <div className="nb-btn-row"><button className="nb-btn primary" type="submit">Sign in</button></div>
          </form> : null}
          {!localMode && mfaRequired ? <form className="nb-card" onSubmit={submitMfa}>
            <div className="nb-crumbs">Step-up authentication</div>
            <h1 className="nb-h1 nb-heading">Verify multi-factor authentication</h1>
            <p className="nb-sub">Enter a current authenticator or unused recovery code before performing security-sensitive central operations.</p>
            <div className="nb-field"><label>MFA code</label><input type="password" autoComplete="one-time-code" required value={mfaCode} onChange={(event) => setMfaCode(event.target.value)} /></div>
            {loginError ? <div className="nb-error">{loginError}</div> : null}
            <div className="nb-btn-row"><button className="nb-btn primary" type="submit">Verify MFA</button><button className="nb-btn" type="button" onClick={logoutOperator}>Sign out</button></div>
          </form> : null}
          {loading && <div className="nb-callout" style={{ marginBottom: 16 }}>Loading VYPER data…</div>}
          {dataError && <div className="nb-error" style={{ marginBottom: 16 }}>{dataError}</div>}
          {screen === "dashboard" && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Dashboard</div>
              <h1 className="nb-h1 nb-heading">Overview</h1>
              <p className="nb-sub">Recent activity, asset counts, and outcome summary.</p>
              <div className="nb-grid-4">
                <div className="nb-metric"><div className="nb-metric-label">Assets tracked</div><div className="nb-metric-value">{counts.total}</div></div>
                <div className="nb-metric"><div className="nb-metric-label">Verified</div><div className="nb-metric-value ok">{counts.verified}</div></div>
                <div className="nb-metric"><div className="nb-metric-label">Failed</div><div className="nb-metric-value bad">{counts.failed}</div></div>
                <div className="nb-metric"><div className="nb-metric-label">Inconclusive</div><div className="nb-metric-value warn">{counts.inconclusive}</div></div>
              </div>
              <div className="nb-grid-2" style={{ marginTop: 16 }}>
                <div className="nb-card">
                  <div className="nb-section-title">Recent jobs <span className="nb-hint">job state and final status shown separately</span></div>
                  <table>
                    <thead><tr><th>Target</th><th>Job state</th><th>Final status</th><th>Dry run</th><th>Updated</th></tr></thead>
                    <tbody>
                      {jobs.slice(0, 5).map((j) => {
                        const meta = getJobStateMeta(j.job_state);
                        const finalMeta = getFinalStatusMeta(j.final_status);
                        return (
                          <tr key={j.id} className="nb-row" onClick={() => goto("jobdetail", { jobId: j.id })}>
                            <td className="strong nb-mono">{j.target}</td>
                            <td><Badge tone={meta.tone}>{meta.label}</Badge></td>
                            <td><Badge tone={finalMeta.tone}>{finalMeta.label}</Badge></td>
                            <td>{j.dry_run ? "Yes" : "No"}</td>
                            <td>{j.updated_at || j.created_at || "—"}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
                <div className="nb-card">
                  <div className="nb-section-title">Recent certificates</div>
                  <table>
                    <thead><tr><th>Certificate</th><th>Outcome</th></tr></thead>
                    <tbody>
                      {certs.slice(0, 4).map((c) => {
                        const finalMeta = getFinalStatusMeta(c.final_status);
                        return (
                          <tr key={c.id} className="nb-row" onClick={() => goto("certificates", { certId: c.id })}>
                            <td className="nb-mono">{c.certificate_id || "—"}</td>
                            <td><Badge tone={finalMeta.tone}>{finalMeta.label}</Badge></td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                  <div className="nb-btn-row"><button className="nb-btn small" onClick={() => goto("certificates")}>View all certificates</button></div>
                </div>
              </div>
            </>
          )}
          {screen === "agents" && !localMode && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Central / Agents</div>
              <h1 className="nb-h1 nb-heading">Remote agents</h1>
              <p className="nb-sub">Agents connect outbound. Destructive requests remain blocked until a local operator approves them.</p>
              <div className="nb-card">
                <div className="nb-section-title">Enrolled agents</div>
                <table>
                  <thead><tr><th>Name</th><th>Hostname</th><th>Platform</th><th>Architecture</th><th>Version</th><th>Status</th><th>Last seen</th><th>Assets</th><th>Active</th><th>Verified</th></tr></thead>
                  <tbody>
                    {remoteAgents.map((agent) => (
                      <tr key={agent.agent_id} className="nb-row" onClick={() => setSelectedAgentId(agent.agent_id)}>
                        <td className="strong">{agent.display_name}</td><td>{agent.hostname}</td><td>{agent.platform}</td>
                        <td>{agent.architecture}</td><td>{agent.agent_version}</td>
                        <td><Badge tone={agent.online ? "ok" : agent.status === "REVOKED" ? "bad" : "pend"}>{agent.status}</Badge></td>
                        <td>{agent.last_seen_at || "Never"}</td><td>{agent.asset_count}</td><td>{agent.active_jobs}</td><td>{agent.verified_jobs}</td>
                      </tr>
                    ))}
                    {remoteAgents.length === 0 && <tr><td colSpan={10}>No enrolled agents.</td></tr>}
                  </tbody>
                </table>
              </div>
              <div className="nb-grid-2">
                <div className="nb-card">
                  <div className="nb-section-title">Synchronized assets <span className="nb-hint">owned by selected agent</span></div>
                  <div className="nb-field"><label>Agent</label><select value={selectedAgentId} onChange={(event) => setSelectedAgentId(event.target.value)}>{remoteAgents.map((agent) => <option key={agent.agent_id} value={agent.agent_id}>{agent.display_name} — {agent.hostname}</option>)}</select></div>
                  <table>
                    <thead><tr><th>Agent</th><th>Path</th><th>Model</th><th>Serial</th><th>Size</th><th>Safety</th></tr></thead>
                    <tbody>{remoteAssets.map((asset) => {
                      const profile = asset.profile_json || {};
                      const safety = profile.is_system_device ? ["bad", "System"]
                        : profile.mounted !== false ? ["warn", profile.mounted ? "Mounted" : "Mount unknown"]
                          : profile.eligible_for_sanitization !== true ? ["bad", "Ineligible"] : ["ok", "Eligible"];
                      return <tr key={asset.id}><td className="nb-mono">{asset.agent_id}</td><td className="nb-mono">{asset.device_path}</td><td>{asset.model || "Unknown"}</td><td>{asset.serial_number || "Unavailable"}</td><td>{formatBytes(asset.size_bytes)}</td><td><Badge tone={safety[0]}>{safety[1]}</Badge></td></tr>;
                    })}</tbody>
                  </table>
                </div>
                <div className="nb-card">
                  <div className="nb-section-title">Create remote job</div>
                  <form onSubmit={submitRemoteJob}>
                    <div className="nb-field"><label>Synchronized asset</label><select value={selectedRemoteAssetIsSelectable ? remoteJobForm.assetId : ""} onChange={(event) => setRemoteJobForm({ ...remoteJobForm, assetId: event.target.value })}><option value="" disabled>Choose an eligible asset</option>{selectableRemoteAssets.map((asset) => <option key={asset.id} value={asset.id}>{asset.device_path} — {asset.model || "Unknown"} — {asset.serial_number || "No serial"}</option>)}</select></div>
                    <div className="nb-field"><label>Remote policy</label><select value={selectedRemotePolicy?.id || ""} onChange={(event) => setRemoteJobForm({ ...remoteJobForm, policyId: event.target.value })}><option value="">Default authorization policy</option>{selectableRemotePolicies.map((policy) => <option key={policy.id} value={policy.id}>{policy.name} — {policy.required_approvals} approval(s)</option>)}</select></div>
                    <div className="nb-field"><label>Execution mode</label><select value={remoteJobForm.executionMode} onChange={(event) => setRemoteJobForm({ ...remoteJobForm, executionMode: event.target.value })}><option value="normal_local">Normal local job</option><option value="boot_sanitize">System-disk temporary boot job</option></select></div>
                    {selectedRemoteAgent && selectedRemoteAsset && <div className="nb-callout" style={{ marginBottom: 12 }}>
                      <b>Authorization context.</b> Target <span className="nb-mono">{selectedRemoteAsset.device_path}</span>; identity <span className="nb-mono">{selectedRemoteAsset.hardware_identity}</span>; agent {selectedRemoteAgent.status}, last heartbeat {selectedRemoteAgent.last_seen_at || "never"}; policy {selectedRemotePolicy?.name || "default"}; eligibility {String(selectedRemoteAsset.profile_json?.eligible_for_sanitization)}; mounted {String(selectedRemoteAsset.profile_json?.mounted)}. Destructive execution is irreversible and still requires independent local approval.
                    </div>}
                    {remoteJobForm.executionMode === "boot_sanitize" && <div className="nb-callout"><b>No-USB boot workflow.</b> The installed OS only prepares a one-shot boot. Sanitization requires fresh confirmation in the independent boot environment.</div>}
                    <div className="nb-check"><input type="checkbox" checked={remoteJobForm.dryRun} onChange={(event) => setRemoteJobForm({ ...remoteJobForm, dryRun: event.target.checked, authorized: event.target.checked ? false : remoteJobForm.authorized })} /><div>Dry run. The agent may execute this automatically if locally configured.</div></div>
                    {!remoteJobForm.dryRun && <div className="nb-check" style={{ marginTop: 8 }}><input type="checkbox" checked={remoteJobForm.authorized} onChange={(event) => setRemoteJobForm({ ...remoteJobForm, authorized: event.target.checked })} /><div><b>Central authorization.</b> This does not replace local operator approval.</div></div>}
                    {remoteJobError && <div className="nb-error">{remoteJobError}</div>}
                    <div className="nb-btn-row"><button className="nb-btn primary" disabled={!selectedRemoteAssetIsSelectable}>Queue remote job</button></div>
                  </form>
                </div>
              </div>
              <div className="nb-card">
                <div className="nb-section-title">Remote job delivery and execution</div>
                <table>
                  <thead><tr><th>Central job</th><th>Agent</th><th>Target</th><th>Mode</th><th>Delivery</th><th>Approvals</th><th>Local state</th><th>Final</th><th>Progress</th><th>Created</th><th>Action</th></tr></thead>
                  <tbody>{centralJobs.map((job) => {
                    const progress = getProgressPresentation(job.progress);
                    return <tr key={job.central_job_id}><td className="nb-mono">{job.central_job_id}</td><td className="nb-mono">{job.agent_id}</td><td className="nb-mono">{job.requested_target}</td><td>{job.execution_mode === "boot_sanitize" ? "SYSTEM-DISK BOOT" : "NORMAL LOCAL"}</td><td><Badge tone={job.waiting_local_approval || job.status === "AWAITING_APPROVAL" ? "warn" : "acc"}>{job.waiting_local_approval ? "WAITING FOR LOCAL APPROVAL" : job.status}</Badge></td><td>{job.approval_count || 0}/{job.required_approvals || 0}</td><td>{job.local_execution_state || "Not started"}</td><td><Badge tone={getFinalStatusMeta(job.final_status).tone}>{getFinalStatusMeta(job.final_status).label}</Badge></td><td>{job.progress ? progress.label : "—"}</td><td>{job.created_at}</td><td>{job.status === "AWAITING_APPROVAL" ? <div className="nb-btn-row"><button className="nb-btn small" onClick={() => decideCentralJob(job, "APPROVED")}>Approve</button><button className="nb-btn small" onClick={() => decideCentralJob(job, "REJECTED")}>Reject</button></div> : "—"}</td></tr>;
                  })}</tbody>
                </table>
              </div>
            </>
          )}
          {screen === "policies" && !localMode && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Central / Policies</div>
              <h1 className="nb-h1 nb-heading">Remote sanitization policies</h1>
              <p className="nb-sub">Organization-scoped policy versions and approval requirements. Revoked policies remain visible for audit but cannot be selected for new jobs.</p>
              <div className="nb-card">
                <table>
                  <thead><tr><th>Organization</th><th>Policy</th><th>Version</th><th>Remote allowed</th><th>Approvals</th><th>System disk</th><th>Status</th></tr></thead>
                  <tbody>
                    {remotePolicies.map((policy) => <tr key={policy.id}>
                      <td>{organizations.find((organization) => organization.id === policy.organization_id)?.name || policy.organization_id}</td>
                      <td className="strong">{policy.name}</td><td>{policy.version}</td>
                      <td>{policy.remote_sanitization_allowed ? "Yes" : "No"}</td>
                      <td>{policy.requires_approval ? policy.required_approvals : 0}</td>
                      <td>{policy.allow_system_disk ? "Allowed through boot workflow" : "Blocked"}</td>
                      <td><Badge tone={policy.revoked_at ? "bad" : "ok"}>{policy.revoked_at ? "REVOKED" : "ACTIVE"}</Badge></td>
                    </tr>)}
                    {remotePolicies.length === 0 && <tr><td colSpan={7}>No remote policies are visible in your organization scope.</td></tr>}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {screen === "security-events" && !localMode && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Central / Security events</div>
              <h1 className="nb-h1 nb-heading">Security events</h1>
              <p className="nb-sub">Organization-scoped control-plane events. These records are distinct from local lifecycle history and the central audit hash chain.</p>
              <div className="nb-card">
                <table>
                  <thead><tr><th>Severity</th><th>Event</th><th>Actor</th><th>Resource</th><th>Agent</th><th>Central job</th><th>Created</th><th>Metadata</th></tr></thead>
                  <tbody>
                    {securityEvents.map((event) => <tr key={event.id}>
                      <td><Badge tone={event.severity === "CRITICAL" || event.severity === "ERROR" ? "bad" : event.severity === "WARNING" ? "warn" : "acc"}>{event.severity}</Badge></td>
                      <td className="strong">{event.event_type}</td><td>{event.actor || "system"}</td>
                      <td className="nb-mono">{event.resource || "—"}</td><td className="nb-mono">{event.agent_id || "—"}</td>
                      <td className="nb-mono">{event.central_job_id || "—"}</td><td>{event.created_at}</td><td className="nb-mono">{JSON.stringify(event.metadata_json || {})}</td>
                    </tr>)}
                    {securityEvents.length === 0 && <tr><td colSpan={8}>No security events are visible in your organization scope.</td></tr>}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {screen === "downloads" && !localMode && dashboardAccessReady && (
            <DownloadsContent apiBase={apiUrl} error={downloadError} release={downloadRelease} dashboard />
          )}
          {screen === "remote-requests" && localMode && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Local console / Remote requests</div>
              <h1 className="nb-h1 nb-heading">Remote sanitization requests</h1>
              <p className="nb-sub">Central authorization never replaces local approval. The local agent re-discovers and validates the selected device immediately before submission.</p>
              <div className="nb-callout" style={{ marginBottom: 12 }}>
                <b>Central sync:</b> {syncStatus?.enrolled ? `Enrolled as ${syncStatus.agent_id}` : "Not enrolled"}
                {syncStatus?.configured ? ` · outbox pending: ${syncStatus.outbox_pending}` : " · configure with vyper enroll"}
              </div>
              <div className="nb-card">
                <div className="nb-section-title">Claimed requests</div>
                <div className="nb-callout" style={{ marginBottom: 12 }}>
                  <b>Remote sanitization request pending approval.</b> Review the stable identity, current local device details, and safety state before approving any destructive request.
                </div>
                <div className="nb-field">
                  <label>ATA password <span className="nb-hint">transient; only applies if the selected policy requires ATA secure erase</span></label>
                  <input type="password" placeholder="Optional" value={remoteApprovalPassword} onChange={(event) => setRemoteApprovalPassword(event.target.value)} />
                </div>
                {remoteApprovalError && <div className="nb-error" style={{ marginBottom: 12 }}>{remoteApprovalError}</div>}
                <table>
                  <thead><tr><th>Central job</th><th>Requested target</th><th>Stable identity</th><th>Mode</th><th>Status</th><th>Expires</th><th>Local job</th><th>Action</th></tr></thead>
                  <tbody>
                    {remoteRequests.map((request) => (
                      <tr key={request.central_job_id}>
                        <td className="nb-mono">{request.central_job_id}</td>
                        <td className="nb-mono">{request.requested_target}</td>
                        <td className="nb-mono">{request.target_identity}</td>
                        <td>{request.payload?.execution_mode === "boot_sanitize" ? "System-disk boot" : request.dry_run ? "Dry run" : "Destructive"}</td>
                        <td><Badge tone={request.status === "SUBMITTED" ? "ok" : request.dry_run ? "acc" : "warn"}>{request.status}</Badge></td>
                        <td>{request.expires_at}</td>
                        <td className="nb-mono">{request.local_job_id || "—"}</td>
                        <td>
                          {request.payload?.execution_mode === "boot_sanitize" ? "Use vyper system-disk prepare" : !request.dry_run && request.status === "WAITING_LOCAL_APPROVAL" ? (
                            <button type="button" className="nb-btn small primary" onClick={() => approveRemoteRequest(request.central_job_id)}>Approve locally</button>
                          ) : "—"}
                        </td>
                      </tr>
                    ))}
                    {remoteRequests.length === 0 && <tr><td colSpan={8}>No remote requests have been claimed by this local agent.</td></tr>}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {screen === "assets" && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Assets</div>
              <h1 className="nb-h1 nb-heading">Asset inventory</h1>
              <p className="nb-sub">Read-only inventory. System-associated devices are blocked from destructive actions.</p>
              <div className="nb-grid-2">
                <div className="nb-card">
                  <div className="nb-filter-row">
                    <select value={assetType} onChange={(e) => setAssetType(e.target.value)}>
                      {["All", "HDD", "SATA SSD", "NVMe"].map((o) => <option key={o}>{o}</option>)}
                    </select>
                    <select value={assetMount} onChange={(e) => setAssetMount(e.target.value)}>
                      {["All", "Mounted", "Unmounted"].map((o) => <option key={o}>{o}</option>)}
                    </select>
                    <div className="nb-search">
                      <Search size={14} aria-hidden="true" />
                      <input type="text" placeholder="Search serial or model" value={assetSearch} onChange={(e) => setAssetSearch(e.target.value)} />
                    </div>
                  </div>
                  <table>
                    <thead><tr><th>Device path</th><th>Model</th><th>Size</th><th>Type</th><th>Serial</th><th>Mounted</th><th>Flags</th></tr></thead>
                    <tbody>
                      {filteredAssets.map((a) => (
                        <tr key={a.id} className="nb-row" style={a.is_system_device ? { background: "#FBEDEA" } : {}} onClick={() => setSelectedAssetId(a.id)}>
                          <td className="strong nb-mono">{a.device_path}</td>
                          <td>{a.model || "Unknown"}</td>
                          <td>{formatBytes(a.size_bytes)}</td>
                          <td>{a.device_type || "Unknown"}</td>
                          <td className="nb-mono">{a.serial_number || "Unavailable"}</td>
                          <td>{a.mounted ? "Yes" : "No"}</td>
                          <td>
                            {a.is_system_device !== false ? (
                              <Badge tone="bad">{a.is_system_device ? "System device" : "Protection unknown"}</Badge>
                            ) : a.profile_error ? (
                              <Badge tone="bad">Profile failed</Badge>
                            ) : a.mounted ? (
                              <Badge tone="warn">Mounted</Badge>
                            ) : (
                              "—"
                            )}
                          </td>
                        </tr>
                      ))}
                      {filteredAssets.length === 0 && <tr><td colSpan={7} style={{ textAlign: "center", color: "#8A8878" }}>No assets match these filters.</td></tr>}
                    </tbody>
                  </table>
                </div>
 
                <div className="nb-card">
                  <div className="nb-section-title">Asset detail <span className="nb-hint">read-only</span></div>

                  {selectedAsset ? (
                    <>
                      <div className="nb-detail-row">
                        <div className="k">device_path</div>
                        <div className="v">{selectedAsset.device_path}</div>
                      </div>

                      <div className="nb-detail-row">
                        <div className="k">device_type</div>
                        <div className="v">{selectedAsset.device_type}</div>
                      </div>

                      <div className="nb-detail-row">
                        <div className="k">serial_number</div>
                        <div className="v">{selectedAsset.serial_number || "Unavailable"}</div>
                      </div>

                      <div className="nb-detail-row">
                        <div className="k">model / size</div>
                        <div className="v">{selectedAsset.model || "Unknown"} / {formatBytes(selectedAsset.size_bytes)}</div>
                      </div>

                      <div className="nb-detail-row">
                        <div className="k">is_system_device</div>
                        <div className="v">{String(selectedAsset.is_system_device)}</div>
                      </div>

                      <div className="nb-detail-row">
                        <div className="k">mounted</div>
                        <div className="v">{String(selectedAsset.mounted)}</div>
                      </div>

                      <div className="nb-detail-row">
                        <div className="k">mounted_partitions</div>
                        <div className="v">
                          {mountedPartitionsText(selectedAsset.mounted_partitions)}
                        </div>
                      </div>

                      {selectedAsset.is_system_device && (
                        <div className="nb-callout" style={{ marginTop: 12 }}>
                          <b>Protected:</b> This is the system disk and cannot be wiped from the currently running operating system.
                        </div>
                      )}
                      {selectedAsset.mounted && (
                        <div className="nb-callout" style={{ marginTop: 12 }}>
                          <b>Mounted device:</b> {mountedPartitionsText(selectedAsset.mounted_partitions)}. Review and unmount every mounted filesystem before destructive execution.
                        </div>
                      )}
                      {selectedAsset.profile_error && (
                        <div className="nb-error" style={{ marginTop: 12 }}>
                          Discovery safety check failed: {selectedAsset.profile_error}. Destructive execution is blocked because device protection could not be established.
                        </div>
                      )}
                    </>
                  ) : (
                    <div className="nb-callout">
                      <b>No assets available.</b> The backend returned no devices.
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
          {screen === "jobs" && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Jobs</div>
              <h1 className="nb-h1 nb-heading">Jobs</h1>
              <p className="nb-sub">Create a sanitization job and monitor existing ones.</p>
              <div className="nb-grid-2">
                <div className="nb-card">
                  <div className="nb-section-title">Job queue</div>
                  <div className="nb-filter-row">
                    <select value={jobStateFilter} onChange={(e) => setJobStateFilter(e.target.value)}>
                      {["All", ...Object.keys(JOB_STATE_META)].map((o) => <option key={o}>{o}</option>)}
                    </select>
                  </div>
                  <table>
                    <thead><tr><th>Target</th><th>Pathway</th><th>Job state</th><th>Final status</th><th>Dry run</th></tr></thead>
                    <tbody>
                      {filteredJobs.map((j) => {
                        const meta = getJobStateMeta(j.job_state);
                        const finalMeta = getFinalStatusMeta(j.final_status);
                        return (
                          <tr key={j.id} className="nb-row" onClick={() => goto("jobdetail", { jobId: j.id })}>
                            <td className="strong nb-mono">{j.target}</td>
                            <td>{j.pathway}</td>
                            <td><Badge tone={meta.tone}>{meta.label}</Badge></td>
                            <td><Badge tone={finalMeta.tone}>{finalMeta.label}</Badge></td>
                            <td>{j.dry_run ? "Yes" : "No"}</td>
                          </tr>
                        );
                      })}
                      {filteredJobs.length === 0 && <tr><td colSpan={5} style={{ textAlign: "center", color: "#8A8878" }}>No jobs in this state.</td></tr>}
                    </tbody>
                  </table>
                </div>
                <div className="nb-card">
                  <div className="nb-section-title">New sanitization job</div>
                  <form onSubmit={submitJob}>
                    <div className="nb-field">
                      <label>Target device</label>
                      {assets.length > 0 ? (
                        <select
                          value={form.target}
                          onChange={(e) => setForm({ ...form, target: e.target.value })}
                        >
                          {assets.map((a) => (
                              <option
                                key={a.id}
                                value={a.device_path}
                                disabled={!form.dryRun && getDeviceProtection(a).blocked}
                              >
                                {a.device_path} — {a.model || "Unknown model"} — {formatBytes(a.size_bytes)} — {a.device_type || "Unknown type"} — {a.serial_number || "No serial"}{getDeviceProtection(a).blocked ? " — PROTECTED" : a.mounted ? " — MOUNTED" : ""}
                              </option>
                            ))}
                        </select>
                      ) : (
                        <div className="nb-callout">
                          <b>No usable assets available.</b> The backend returned no devices.
                        </div>
                      )}
                      {selectedTargetProtection.reason && (
                        <div className={selectedTargetProtection.blocked ? "nb-error" : "nb-callout"} style={{ marginTop: 8 }}>
                          {selectedTargetProtection.reason}
                        </div>
                      )}
                      {selectedTargetDevice?.mounted && (
                        <div className="nb-callout" style={{ marginTop: 8 }}>
                          <b>Mounted device:</b> {mountedPartitionsText(selectedTargetDevice.mounted_partitions)}. Destructive execution requires explicit authorization and should only occur after unmounting.
                        </div>
                      )}
                    </div>
                    <div className="nb-field" style={{ marginBottom: 12 }}>
                      <div className="nb-check">
                        <input type="checkbox" checked={form.dryRun} onChange={(e) => setForm({ ...form, dryRun: e.target.checked, authorized: e.target.checked ? false : form.authorized, ataPassword: e.target.checked ? "" : form.ataPassword })} />
                        <div>Dry run — plan only, no destructive action is taken.</div>
                      </div>
                    </div>
                    <div className="nb-field" style={{ marginBottom: 8 }}>
                      <div className="nb-check">
                        <input type="checkbox" checked={form.authorized} onChange={(e) => setForm({ ...form, authorized: e.target.checked, ataPassword: e.target.checked ? form.ataPassword : "" })} />
                        <div><b>I authorize this destructive operation.</b> Required before submission unless dry run is checked.</div>
                      </div>
                    </div>
                    {!form.dryRun && form.authorized && (
                      <div className="nb-field">
                        <label>ATA password <span className="nb-hint">optional; used only if ATA secure erase is selected</span></label>
                        <input type="password" autoComplete="off" placeholder="Transient ATA password" value={form.ataPassword} onChange={(e) => setForm({ ...form, ataPassword: e.target.value })} />
                      </div>
                    )}
                    {formError && <div className="nb-error">{formError}</div>}
                    <div className="nb-btn-row">
                      <button type="submit" className="nb-btn primary" disabled={!form.dryRun && selectedTargetProtection.blocked}>Submit job</button>
                      <button type="button" className="nb-btn" onClick={() => setForm({ target: assets.find((a) => !getDeviceProtection(a).blocked)?.device_path || "", ataPassword: "", dryRun: true, authorized: false })}>Reset</button>
                    </div>
                  </form>
                </div>
              </div>
            </>
          )}
          {screen === "jobdetail" && selectedJob && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Jobs / {selectedJob.target}</div>
              <h1 className="nb-h1 nb-heading">Job detail — <span className="nb-mono">{selectedJob.target}</span></h1>
              <p className="nb-sub">Full pipeline state chain. Success is treated as non-final until verification and a certificate exist.</p>
              <div className="nb-card">
                <div className="nb-section-title">Pipeline state</div>
                <Pipeline jobState={selectedJob.job_state} />
                <div className="nb-callout" style={{ marginTop: 12 }}>
                  <b>job_state:</b> {selectedJob.job_state} &nbsp; · &nbsp; <b>final_status:</b> {selectedJob.final_status || "not yet set"} &nbsp; · &nbsp; <b>dry_run:</b> {String(selectedJob.dry_run)}
                </div>
                {selectedJob.progress && selectedJobProgress.kind === "bytes" && (
                  <div className="nb-callout" style={{ marginTop: 12 }}>
                    <b>Measured progress:</b> {selectedJobProgress.label} ({selectedJobProgress.percentage.toFixed(1)}%)
                    <div className="nb-progress" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={selectedJobProgress.percentage}>
                      <div className="nb-progress-fill" style={{ width: `${selectedJobProgress.percentage}%` }} />
                    </div>
                  </div>
                )}
                {selectedJob.progress && selectedJobProgress.kind === "indeterminate" && !TERMINAL_JOB_STATES.has(selectedJob.job_state) && (
                  <div className="nb-callout" style={{ marginTop: 12 }}>
                    <span className="nb-spinner" aria-hidden="true" />{selectedJobProgress.label}
                  </div>
                )}
              </div>
              <div className="nb-grid-2">
                <div>
                  <div className="nb-section-title" style={{ marginTop: 4 }}>Payloads <span className="nb-hint">expandable, not raw blobs</span></div>
                  <JsonPanel title="execution_json" json={selectedJob.execution_json} defaultOpen />
                  <JsonPanel title="verification_json" json={selectedJob.verification_json} />
                  <JsonPanel title="evidence_json" json={selectedJob.evidence_json} />
                  <JsonPanel title="state_history" json={selectedJob.state_history_json} />
                  {selectedJob.error_json && <JsonPanel title="sanitized_error" json={selectedJob.error_json} defaultOpen />}
                  {selectedJobCertificateView && (
                    <div className="nb-stamp-card" style={{ marginTop: 14 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                        {selectedJobCertificateView.successfulClaim
                          ? <ShieldCheck size={18} aria-hidden="true" />
                          : <CircleDot size={18} aria-hidden="true" />}
                        <span className="nb-heading" style={{ fontSize: 13 }}>{selectedJobCertificateView.title}</span>
                        <Badge tone={selectedJobCertificateView.tone}>{selectedJobCertificateView.detail}</Badge>
                      </div>
                      <div className="nb-detail-row"><div className="k">certificate_id</div><div className="v">{selectedJobCertificateView.certificateId}</div></div>
                      <div className="nb-detail-row"><div className="k">certificate_hash</div><div className="v">{selectedJobCertificateView.certificateHash}</div></div>
                      <div className="nb-detail-row"><div className="k">outcome_kind</div><div className="v">{selectedJobCertificateView.outcomeKind}</div></div>
                      <div className="nb-detail-row"><div className="k">successful_sanitization_claim</div><div className="v">{String(selectedJobCertificateView.successfulClaim)}</div></div>
                      <JsonPanel title="certificate_json" json={selectedJobCertificateView.certificateJson} />
                    </div>
                  )}
                </div>
                <div>
                  <div className="nb-section-title" style={{ marginTop: 4 }}>Audit log entries <span className="nb-hint">this job</span></div>
                  <div className="nb-card" style={{ padding: 0 }}>
                    <table>
                      <thead><tr><th>Action</th><th>Actor</th><th>Target</th><th>Created</th></tr></thead>
                      <tbody>
                        {selectedJobAuditLogs.map((log) => {
                          const audit = auditLogView(log);
                          return (
                            <tr key={log.id}>
                              <td>{audit.action}</td>
                              <td>{audit.actor}</td>
                              <td className="nb-mono">{audit.target}</td>
                              <td className="nb-mono">{audit.createdAt}</td>
                            </tr>
                          );
                        })}
                        {selectedJobAuditLogs.length === 0 && (
                          <tr><td colSpan={4} style={{ textAlign: "center", color: "#8A8878" }}>No audit entries for this job.</td></tr>
                        )}
                      </tbody>
                    </table>
                  </div>
                  {!selectedJob.certificate && (
                    <div className="nb-callout" style={{ marginTop: 12 }}>
                      <CircleDot size={12} aria-hidden="true" style={{ verticalAlign: "-1px", marginRight: 4 }} />
                      Certificate panel appears here only once verified and the certificate payload is returned — never shown speculatively.
                    </div>
                  )}
                </div>
              </div>
            </>
          )}
          {screen === "certificates" && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Certificates</div>
              <h1 className="nb-h1 nb-heading">Certificates</h1>
              <p className="nb-sub">Certificate index and detail, with hash and sanitization claim.</p>
              <div className="nb-grid-2">
                <div className="nb-card">
                  <table>
                    <thead><tr><th>Certificate</th><th>Target</th><th>Outcome</th><th>Claim</th></tr></thead>
                    <tbody>
                      {certs.length === 0 ? (
                        <tr>
                          <td
                            colSpan={4}
                            style={{ textAlign: "center", color: "#8A8878" }}
                          >
                            No certificates available.
                          </td>
                        </tr>
                      ) : (
                        certs.map((c) => {
                          const finalMeta = getFinalStatusMeta(c.final_status);
                          return (
                            <tr
                              key={c.id}
                              className="nb-row"
                              onClick={() => setSelectedCertId(c.id)}
                            >
                              <td className="nb-mono">{c.certificate_id || "—"}</td>
                              <td className="nb-mono">{c.target || "—"}</td>
                              <td><Badge tone={finalMeta.tone}>{finalMeta.label}</Badge></td>
                              <td>{c.successful_sanitization_claim ? "Successful" : "Not claimed"}</td>
                            </tr>
                          );
                        })
                      )}
                    </tbody>
                  </table>
                </div>
                {selectedCert && selectedCertView ? (
                  <div className="nb-stamp-card">
                    <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                      {selectedCertView.successfulClaim
                        ? <ShieldCheck size={20} aria-hidden="true" />
                        : <CircleDot size={20} aria-hidden="true" />}
                      <span className="nb-heading" style={{ fontSize: 14 }}>
                        {selectedCertView.title}
                      </span>
                      <Badge tone={selectedCertView.tone}>{selectedCertView.detail}</Badge>
                    </div>

                    <div className="nb-detail-row">
                      <div className="k">certificate_id</div>
                      <div className="v">{selectedCertView.certificateId}</div>
                    </div>

                    <div className="nb-detail-row">
                      <div className="k">job_id</div>
                      <div className="v">{selectedCert.job_id}</div>
                    </div>

                    <div className="nb-detail-row">
                      <div className="k">target</div>
                      <div className="v">{selectedCert.target}</div>
                    </div>

                    <div className="nb-detail-row">
                      <div className="k">final_status</div>
                      <div className="v">
                        <Badge
                          tone={selectedCertFinalMeta.tone}
                          stamp
                        >
                          {selectedCertFinalMeta.label}
                        </Badge>
                      </div>
                    </div>

                    <div className="nb-detail-row">
                      <div className="k">successful_sanitization_claim</div>
                      <div className="v">{String(selectedCertView.successfulClaim)}</div>
                    </div>

                    <div className="nb-detail-row">
                      <div className="k">outcome_kind</div>
                      <div className="v">{selectedCertView.outcomeKind}</div>
                    </div>

                    <div className="nb-detail-row">
                      <div className="k">certificate_hash</div>
                      <div className="v">{selectedCertView.certificateHash}</div>
                    </div>

                    <JsonPanel
                      title="certificate_json"
                      json={selectedCertView.certificateJson}
                    />
                  </div>
                ) : (
                  <div className="nb-callout">
                    <b>No certificates available.</b> The backend returned no certificates.
                  </div>
                )}
              </div>
            </>
          )}
 
          {screen === "auditlogs" && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Audit logs</div>
              <h1 className="nb-h1 nb-heading">Audit trail</h1>
              <p className="nb-sub">{localMode ? "Locally recorded job lifecycle events with their original sequence and timestamps." : "Request and response entries with actor metadata and timestamps."}</p>
              <div className="nb-card">
                <div className="nb-filter-row">
                  <div className="nb-search">
                    <Search size={14} aria-hidden="true" />
                    <input type="text" placeholder="Filter by actor" value={auditActor} onChange={(e) => setAuditActor(e.target.value)} />
                  </div>
                  <select value={auditAction} onChange={(e) => setAuditAction(e.target.value)}>
                    <option>All</option>
                    {[...new Set(auditLogs.map((l) => l.action))].map((a) => <option key={a}>{a}</option>)}
                  </select>
                </div>
                <table>
                  <thead><tr><th>Action</th><th>Actor</th><th>Target</th><th>Request</th><th>Response</th><th>Created</th></tr></thead>
                  <tbody>
                    {filteredAuditLogs.map((log) => {
                      const audit = auditLogView(log);
                      return (
                        <tr key={log.id} className="nb-row">
                          <td className="strong">{audit.action}</td>
                          <td>{audit.actor}</td>
                          <td className="nb-mono">{audit.target}</td>
                          <td className="nb-mono">{JSON.stringify(audit.requestJson)}</td>
                          <td className="nb-mono">{JSON.stringify(audit.responseJson)}</td>
                          <td className="nb-mono">{audit.createdAt}</td>
                        </tr>
                      );
                    })}
                    {filteredAuditLogs.length === 0 && <tr><td colSpan={6} style={{ textAlign: "center", color: "#8A8878" }}>No entries match these filters.</td></tr>}
                  </tbody>
                </table>
              </div>
            </>
          )}
          {screen === "settings" && dashboardAccessReady && (
            <>
              <div className="nb-crumbs">Settings</div>
              <h1 className="nb-h1 nb-heading">Settings</h1>
              <p className="nb-sub">{localMode ? "Local mode connects directly to the execution service on this machine." : "Central mode connects to the persisted management API."}</p>
			  <p className="nb-mono">VYPER {PRODUCT_VERSION}</p>
              <div className="nb-card" style={{ maxWidth: 460 }}>
                <div className="nb-field">
                  <label>{localMode ? "NEXT_PUBLIC_VYPER_LOCAL_AGENT_API_BASE_URL" : "NEXT_PUBLIC_VYPER_API_BASE_URL"}</label>
                  <input type="text" value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} />
                </div>
                <div className="nb-field">
                  {localMode ? <><label>Local API credential</label>
                  <input type="password" autoComplete="off" placeholder="Loopback local-agent credential" value={apiKey} onChange={(e) => setApiKey(e.target.value)} /></> : null}
                  <div className="nb-help">Sent as a request header when set.</div>
                </div>
                <div className="nb-btn-row">
                  <button className="nb-btn primary" type="button" onClick={persistSettings}>Save settings</button>
                  <button className="nb-btn" type="button" onClick={resetSettings}>Clear / reset</button>
                  {savedMsg && <Badge tone="ok">{savedMsg}</Badge>}
                </div>
              </div>
              {!localMode && (
                <div className="nb-card" style={{ maxWidth: 460, marginTop: 12 }}>
                  <div className="nb-field">
                    <label>Change password</label>
                    <input type="password" autoComplete="new-password" value={debugPassword} onChange={(e) => setDebugPassword(e.target.value)} />
                  </div>
                  <div className="nb-btn-row">
                    <button className="nb-btn primary" type="button" onClick={changeDebugPassword}>Change</button>
                    {debugPasswordMsg && <Badge tone={debugPasswordMsg === "Changed." ? "ok" : "bad"}>{debugPasswordMsg}</Badge>}
                  </div>
                </div>
              )}
            </>
          )}
        </main>
      </div>
    </div>
  );
}
