"use client";
import { useState, useEffect, useRef } from "react";
import {
  LayoutGrid, HardDrive, ListChecks, FileCheck2, ScrollText, Settings as SettingsIcon,
  ChevronDown, ShieldCheck, Lock, Search, X, Check, TriangleAlert, CircleDot,
} from "lucide-react";

const STAGES = ["Profiling", "Policy", "Execution", "Verification", "Evidence", "Certificate"];

const STATE_META = {
  PENDING: { stage: -1, tone: "pend", label: "Pending" },
  PROFILING: { stage: 0, tone: "acc", label: "Profiling" },
  POLICY_SELECTED: { stage: 1, tone: "acc", label: "Policy selected" },
  AWAITING_AUTHORIZATION: { stage: 1, tone: "warn", label: "Awaiting authorization" },
  RUNNING: { stage: 2, tone: "acc", label: "Running" },
  VERIFYING: { stage: 3, tone: "acc", label: "Verifying" },
  VERIFIED: { stage: 5, tone: "ok", label: "Verified" },
  FAILED: { stage: 2, tone: "bad", label: "Failed" },
  INCONCLUSIVE: { stage: 3, tone: "warn", label: "Inconclusive" },
  UNSUPPORTED: { stage: 0, tone: "bad", label: "Unsupported" },
  CANCELLED: { stage: -1, tone: "pend", label: "Cancelled" },
};

const initialAssets = [
  { id: "a1", device_path: "/dev/sdb", model: "WD Blue 1TB", device_type: "HDD", serial_number: "WD-WX61A83K7291", is_system_device: false, mounted: false, mounted_partitions: [] },
  { id: "a2", device_path: "/dev/sdc", model: "Samsung 870 EVO", device_type: "SSD", serial_number: "S6B2NX0T400123", is_system_device: false, mounted: true, mounted_partitions: ["/data", "/backup"] },
  { id: "a3", device_path: "/dev/nvme0n1", model: "Crucial P3 500GB", device_type: "NVMe", serial_number: "23091500A8F2", is_system_device: false, mounted: false, mounted_partitions: [] },
  { id: "a4", device_path: "/dev/sda", model: "System SSD 256GB", device_type: "SSD", serial_number: "SYS-88213C009", is_system_device: true, mounted: true, mounted_partitions: ["/", "/boot"] },
  { id: "a5", device_path: "/dev/sde", model: "Seagate Barracuda 2TB", device_type: "HDD", serial_number: "ST2000-DM008-Z1", is_system_device: false, mounted: false, mounted_partitions: [] },
];

const initialJobs = [
  {
    id: "job_5511", target: "/dev/sdb", pathway: "ATA secure erase", job_state: "VERIFYING", final_status: null,
    dry_run: false, outcome_kind: null, successful_sanitization_claim: null, updated: "2m ago",
    execution_json: '{\n  "pathway": "ata_secure_erase",\n  "duration_seconds": 842,\n  "outcome_kind": "completed"\n}',
    verification_json: '{\n  "status": "in_progress",\n  "method": "sample_read_verify"\n}',
    evidence_json: '{\n  "status": "pending"\n}',
    certificate: null,
    audit: [
      { action: "job.created", actor: "operator_1", at: "09:11:58" },
      { action: "job.execution.completed", actor: "agent", at: "09:25:40" },
      { action: "job.verification.started", actor: "agent", at: "09:25:41" },
    ],
  },
  {
    id: "job_5510", target: "/dev/nvme0n1", pathway: "NVMe sanitize", job_state: "VERIFIED", final_status: "SUCCESS",
    dry_run: false, outcome_kind: "completed", successful_sanitization_claim: true, updated: "14m ago",
    execution_json: '{\n  "pathway": "nvme_sanitize",\n  "duration_seconds": 210,\n  "outcome_kind": "completed"\n}',
    verification_json: '{\n  "status": "passed",\n  "method": "full_read_verify"\n}',
    evidence_json: '{\n  "status": "collected",\n  "artifact": "evidence_5510.bin"\n}',
    certificate: { id: "cert_9f2ac103", hash: "a3f92e17c9bb21be", standard: "NIST 800-88" },
    audit: [
      { action: "job.created", actor: "operator_1", at: "09:11:58" },
      { action: "job.execution.completed", actor: "agent", at: "09:25:40" },
      { action: "certificate.issued", actor: "agent", at: "09:41:02" },
    ],
  },
  {
    id: "job_5498", target: "/dev/sdc", pathway: "Overwrite (3-pass)", job_state: "FAILED", final_status: "FAILURE",
    dry_run: false, outcome_kind: "error", successful_sanitization_claim: false, updated: "1h ago",
    execution_json: '{\n  "pathway": "overwrite_3pass",\n  "outcome_kind": "error",\n  "error": "device_busy"\n}',
    verification_json: '{\n  "status": "not_run"\n}',
    evidence_json: '{\n  "status": "not_collected"\n}',
    certificate: null,
    audit: [
      { action: "job.created", actor: "operator_2", at: "07:58:02" },
      { action: "job.execution.failed", actor: "agent", at: "08:02:11" },
    ],
  },
  {
    id: "job_5480", target: "/dev/sde", pathway: "Overwrite (3-pass)", job_state: "AWAITING_AUTHORIZATION", final_status: null,
    dry_run: true, outcome_kind: null, successful_sanitization_claim: null, updated: "3h ago",
    execution_json: '{\n  "status": "not_started"\n}',
    verification_json: '{\n  "status": "not_run"\n}',
    evidence_json: '{\n  "status": "not_collected"\n}',
    certificate: null,
    audit: [{ action: "job.created", actor: "operator_1", at: "06:40:19" }],
  },
];

const initialCerts = [
  { id: "cert_9f2ac103", job_id: "job_5510", target: "/dev/nvme0n1", final_status: "SUCCESS", claim: true, hash: "a3f92e17c9bb21be", standard: "NIST 800-88", issued: "09:41:02" },
  { id: "cert_7b41e88a", job_id: "job_5442", target: "/dev/sde", final_status: "SUCCESS", claim: true, hash: "77c1f0aa982be411", standard: "NIST 800-88", issued: "Yesterday" },
  { id: "cert_2d9040f1", job_id: "job_5401", target: "/dev/sdc", final_status: "FAILURE", claim: false, hash: "—", standard: "—", issued: "Yesterday" },
];

const initialAuditLogs = [
  { action: "job.created", actor: "operator_1", request: '{ target: "/dev/sdb" }', response: '{ job_id: "job_5511" }', at: "09:11:58" },
  { action: "certificate.issued", actor: "agent", request: '{ job_id: "job_5510" }', response: "{ status: 200 }", at: "09:41:02" },
  { action: "job.execution.failed", actor: "agent", request: '{ job_id: "job_5498" }', response: '{ error: "device_busy" }', at: "08:02:11" },
  { action: "job.created", actor: "operator_2", request: '{ target: "/dev/sdc" }', response: '{ job_id: "job_5498" }', at: "07:58:02" },
];

function Badge({ tone = "pend", children, stamp }) {
  return (
    <span className={"nb-badge nb-tone-" + tone + (stamp ? " nb-stamp" : "")}>
      {children}
    </span>
  );
}

function JsonPanel({ title, json, defaultOpen }) {
  const [open, setOpen] = useState(!!defaultOpen);
  return (
    <div className={"nb-json" + (open ? " open" : "")}>
      <button className="nb-json-head" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span>{title}</span>
        <ChevronDown size={16} className="nb-chev" />
      </button>
      {open && <pre className="nb-json-body">{json}</pre>}
    </div>
  );
}

function Pipeline({ jobState }) {
  const meta = STATE_META[jobState] || STATE_META.PENDING;
  const failedAt = jobState === "FAILED" || jobState === "UNSUPPORTED" ? meta.stage : -1;
  return (
    <div className="nb-pipeline">
      {STAGES.map((label, i) => {
        let cls = "pend";
        if (failedAt === i) cls = "bad";
        else if (i < meta.stage || jobState === "VERIFIED") cls = "done";
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
  const [screen, setScreen] = useState("dashboard");
  const [assets] = useState(initialAssets);
  const [jobs, setJobs] = useState(initialJobs);
  const [certs, setCerts] = useState(initialCerts);
  const [auditLogs, setAuditLogs] = useState(initialAuditLogs);

  const [selectedAssetId, setSelectedAssetId] = useState(initialAssets[1].id);
  const [selectedJobId, setSelectedJobId] = useState(initialJobs[0].id);
  const [selectedCertId, setSelectedCertId] = useState(initialCerts[0].id);

  const [assetType, setAssetType] = useState("All");
  const [assetMount, setAssetMount] = useState("All");
  const [assetSearch, setAssetSearch] = useState("");

  const [jobStateFilter, setJobStateFilter] = useState("All");

  const [auditActor, setAuditActor] = useState("");
  const [auditAction, setAuditAction] = useState("All");

  const [form, setForm] = useState({ target: initialAssets[0].device_path, ataPassword: "", dryRun: true, authorized: false });
  const [formError, setFormError] = useState("");

  const [apiUrl, setApiUrl] = useState("https://api.vyper.internal");
  const [apiKey, setApiKey] = useState("");
  const [savedMsg, setSavedMsg] = useState("");

  const timers = useRef([]);
  const nextJobSequence = useRef(5512);
  const nextCertSequence = useRef(10);
  useEffect(() => () => timers.current.forEach(clearTimeout), []);

  function goto(screenId, opts) {
    setScreen(screenId);
    if (opts?.jobId) setSelectedJobId(opts.jobId);
    if (opts?.certId) setSelectedCertId(opts.certId);
  }

  function updateJob(id, patch) {
    setJobs((prev) => prev.map((j) => (j.id === id ? { ...j, ...patch } : j)));
  }
  function pushAudit(jobId, entry) {
    setJobs((prev) => prev.map((j) => (j.id === jobId ? { ...j, audit: [...j.audit, entry] } : j)));
    setAuditLogs((prev) => [{ action: entry.action, actor: entry.actor, request: '{ job_id: "' + jobId + '" }', response: "{ status: 200 }", at: entry.at }, ...prev]);
  }

  function submitJob(e) {
    e.preventDefault();
    if (!form.target) {
      setFormError("Choose a target device before submitting.");
      return;
    }
    if (!form.dryRun && !form.authorized) {
      setFormError("Check the authorization box or enable dry run before submitting.");
      return;
    }
    setFormError("");
    const id = "job_" + nextJobSequence.current++;
    const now = new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    const newJob = {
      id, target: form.target, pathway: form.dryRun ? "Plan only" : "ATA secure erase",
      job_state: "PENDING", final_status: null, dry_run: form.dryRun, outcome_kind: null,
      successful_sanitization_claim: null, updated: "just now",
      execution_json: '{\n  "status": "not_started"\n}', verification_json: '{\n  "status": "not_run"\n}',
      evidence_json: '{\n  "status": "not_collected"\n}', certificate: null,
      audit: [{ action: "job.created", actor: "operator_1", at: now }],
    };
    setJobs((prev) => [newJob, ...prev]);
    setAuditLogs((prev) => [{ action: "job.created", actor: "operator_1", request: '{ target: "' + form.target + '" }', response: '{ job_id: "' + id + '" }', at: now }, ...prev]);
    goto("jobdetail", { jobId: id });
    runPipeline(id, form.dryRun);
    setForm({ target: form.target, ataPassword: "", dryRun: form.dryRun, authorized: false });
  }

  function runPipeline(id, dryRun) {
    const at = () => new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
    const t1 = setTimeout(() => updateJob(id, { job_state: "PROFILING" }), 900);
    const t2 = setTimeout(() => updateJob(id, { job_state: "POLICY_SELECTED" }), 1800);
    timers.current.push(t1, t2);
    if (dryRun) {
      const t3 = setTimeout(() => {
        updateJob(id, { job_state: "AWAITING_AUTHORIZATION" });
        pushAudit(id, { action: "job.plan.ready", actor: "agent", at: at() });
      }, 2700);
      timers.current.push(t3);
      return;
    }
    const t3 = setTimeout(() => updateJob(id, { job_state: "RUNNING" }), 2700);
    const t4 = setTimeout(() => {
      updateJob(id, {
        job_state: "VERIFYING",
        execution_json: '{\n  "pathway": "ata_secure_erase",\n  "duration_seconds": 512,\n  "outcome_kind": "completed"\n}',
      });
      pushAudit(id, { action: "job.execution.completed", actor: "agent", at: at() });
    }, 4200);
    const t5 = setTimeout(() => {
      const certSequence = String(nextCertSequence.current++).padStart(8, "0");
      const certId = "cert_" + certSequence;
      const hash = ("vyper" + id + certSequence).replace(/[^a-zA-Z0-9]/g, "").padEnd(16, "0").slice(0, 16);
      updateJob(id, {
        job_state: "VERIFIED", final_status: "SUCCESS", outcome_kind: "completed", successful_sanitization_claim: true,
        verification_json: '{\n  "status": "passed",\n  "method": "full_read_verify"\n}',
        evidence_json: '{\n  "status": "collected",\n  "artifact": "evidence_' + id + '.bin"\n}',
        certificate: { id: certId, hash, standard: "NIST 800-88" },
      });
      setJobs((prev) => {
        const j = prev.find((x) => x.id === id);
        setCerts((c) => [{ id: certId, job_id: id, target: j?.target || "", final_status: "SUCCESS", claim: true, hash, standard: "NIST 800-88", issued: at() }, ...c]);
        return prev;
      });
      pushAudit(id, { action: "certificate.issued", actor: "agent", at: at() });
    }, 5600);
    timers.current.push(t3, t4, t5);
  }

  const filteredAssets = assets.filter((a) => {
    if (assetType !== "All" && a.device_type !== assetType) return false;
    if (assetMount === "Mounted" && !a.mounted) return false;
    if (assetMount === "Unmounted" && a.mounted) return false;
    const q = assetSearch.toLowerCase();
    if (q && !a.model.toLowerCase().includes(q) && !a.serial_number.toLowerCase().includes(q)) return false;
    return true;
  });
  const selectedAsset = assets.find((a) => a.id === selectedAssetId) || assets[0];

  const filteredJobs = jobs.filter((j) => jobStateFilter === "All" || j.job_state === jobStateFilter);
  const selectedJob = jobs.find((j) => j.id === selectedJobId) || jobs[0];

  const selectedCert = certs.find((c) => c.id === selectedCertId) || certs[0];

  const filteredAuditLogs = auditLogs.filter((l) => {
    if (auditAction !== "All" && l.action !== auditAction) return false;
    if (auditActor && !l.actor.toLowerCase().includes(auditActor.toLowerCase())) return false;
    return true;
  });

  const counts = {
    total: assets.length,
    verified: jobs.filter((j) => j.job_state === "VERIFIED").length,
    failed: jobs.filter((j) => j.job_state === "FAILED").length,
    inconclusive: jobs.filter((j) => j.job_state === "INCONCLUSIVE").length,
  };

  const NAV = [
    { id: "dashboard", label: "Dashboard", icon: LayoutGrid },
    { id: "assets", label: "Assets", icon: HardDrive },
    { id: "jobs", label: "Jobs", icon: ListChecks },
    { id: "certificates", label: "Certificates", icon: FileCheck2 },
    { id: "auditlogs", label: "Audit logs", icon: ScrollText },
    { id: "settings", label: "Settings", icon: SettingsIcon },
  ];

  return (
    <div className="nb-root">
      <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;600&display=swap" />
      <style>{`
        .nb-root{
          --bg:#EDEAE0; --ink:#14141A; --paper:#FFFFFF;
          --accent:#3A5CFF; --accent-ink:#0B1A80;
          --pink:#FF5FA2; --pink-ink:#7A0E45;
          --ok-bg:#CFFCE9; --ok-ink:#04724D; --ok-line:#04A46D;
          --bad-bg:#FFDADA; --bad-ink:#8C1010; --bad-line:#E23333;
          --warn-bg:#FFF2C2; --warn-ink:#7A5900; --warn-line:#E0AC1C;
          --pend-bg:#DEDBCF; --pend-ink:#4A483F; --pend-line:#9C9A8D;
          --acc-bg:#DCE3FF; --acc-ink:#0B1A80; --acc-line:#3A5CFF;
          --edge:clamp(0.75rem,2vw,1.875rem);
          --gap:clamp(0.75rem,1.5vw,1rem);
          --card-pad:clamp(0.875rem,1.6vw,1.125rem);
          --shadow:clamp(0.25rem,0.8vw,0.5rem);
          font-family:'Inter',-apple-system,sans-serif;
          background:var(--bg); color:var(--ink);
          border:3px solid var(--ink); border-radius:0;
          box-shadow:var(--shadow) var(--shadow) 0 var(--ink);
          overflow:hidden;
          width:min(100%,calc(100vw - 1rem));
          min-height:100svh;
          margin:0 auto;
        }
        .nb-root *{box-sizing:border-box;}
        .nb-heading{font-family:'Space Grotesk',sans-serif; font-weight:700;}
        .nb-mono{font-family:'JetBrains Mono',monospace; overflow-wrap:anywhere;}
        .nb-shell{display:grid; grid-template-columns:minmax(11rem,14rem) minmax(0,1fr); min-height:100svh;}
        .nb-sidebar{background:var(--ink); color:#fff; padding:clamp(0.875rem,1.6vw,1.125rem) 0; display:flex; flex-direction:column; border-right:3px solid var(--ink); min-width:0;}
        .nb-brand{padding:0 var(--card-pad) var(--card-pad); margin-bottom:0.5rem; border-bottom:3px solid #3A3A44;}
        .nb-brand-mark{width:2.125rem; aspect-ratio:1; background:var(--accent); border:2.5px solid #fff; display:flex; align-items:center; justify-content:center; font-weight:700; font-family:'Space Grotesk',sans-serif; margin-bottom:0.5rem; box-shadow:3px 3px 0 #fff;}
        .nb-brand-name{font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:1rem; letter-spacing:0.02em;}
        .nb-brand-sub{font-size:0.656rem; color:#B8B7C4; margin-top:0.125rem; text-transform:uppercase; letter-spacing:0.06em;}
        .nb-nav{padding:0.625rem; flex:1; min-width:0;}
        .nb-nav-item{display:flex; align-items:center; gap:0.55rem; padding:0.6rem 0.65rem; font-size:0.8125rem; font-weight:700; font-family:'Space Grotesk',sans-serif; color:#C9C8D4; cursor:pointer; margin-bottom:0.25rem; border:2px solid transparent; background:none; width:100%; text-align:left; white-space:nowrap;}
        .nb-nav-item:hover{border-color:#3A3A44;}
        .nb-nav-item.active{background:var(--accent); color:#fff; border-color:#fff; box-shadow:3px 3px 0 #fff;}
        .nb-sidebar-footer{padding:0.875rem var(--card-pad) 0.25rem; border-top:3px solid #3A3A44; font-size:0.6875rem; color:#B8B7C4; display:flex; align-items:center; gap:0.375rem;}
        .nb-dot{width:0.5rem; aspect-ratio:1; background:var(--ok-line); border-radius:50%; flex:0 0 auto;}

        .nb-main{padding:var(--edge); overflow:auto; min-width:0;}
        .nb-crumbs{font-size:0.72rem; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; color:#6B6A60; margin-bottom:0.375rem;}
        .nb-h1{font-size:clamp(1.45rem,2.2vw,1.8rem); margin:0 0 0.375rem; display:flex; align-items:center; gap:0.625rem; flex-wrap:wrap;}
        .nb-sub{font-size:clamp(0.8125rem,1.1vw,0.9rem); color:#4A4940; margin:0 0 clamp(1rem,2vw,1.4rem); max-width:46rem;}

        .nb-card{background:var(--paper); border:3px solid var(--ink); box-shadow:calc(var(--shadow) * 0.75) calc(var(--shadow) * 0.75) 0 var(--ink); padding:var(--card-pad); margin-bottom:var(--gap); min-width:0; overflow:auto;}
        .nb-grid-4{display:grid; grid-template-columns:repeat(auto-fit,minmax(min(100%,10rem),1fr)); gap:var(--gap);}
        .nb-grid-2{display:grid; grid-template-columns:minmax(0,1.4fr) minmax(min(100%,18rem),1fr); gap:var(--gap); align-items:start;}
        .nb-grid-2 > *{min-width:0;}
        @media (max-width:64rem){ .nb-grid-2{grid-template-columns:1fr;} }

        .nb-metric{background:var(--paper); border:3px solid var(--ink); box-shadow:calc(var(--shadow) * 0.65) calc(var(--shadow) * 0.65) 0 var(--ink); padding:clamp(0.8rem,1.4vw,1rem);}
        .nb-metric-label{font-size:0.656rem; text-transform:uppercase; font-weight:700; letter-spacing:0.05em; color:#6B6A60;}
        .nb-metric-value{font-family:'Space Grotesk',sans-serif; font-size:clamp(1.65rem,3vw,2rem); font-weight:700; margin-top:0.25rem;}
        .nb-metric-value.ok{color:var(--ok-ink);} .nb-metric-value.bad{color:var(--bad-ink);} .nb-metric-value.warn{color:var(--warn-ink);}

        .nb-section-title{font-family:'Space Grotesk',sans-serif; font-weight:700; font-size:0.875rem; margin:0 0 0.75rem; display:flex; align-items:center; justify-content:space-between; gap:0.5rem; flex-wrap:wrap;}
        .nb-hint{font-size:0.6875rem; color:#8A8878; font-weight:400; font-family:'Inter',sans-serif;}

        table{width:100%; min-width:32rem; border-collapse:collapse; font-size:0.781rem;}
        th{text-align:left; font-size:0.656rem; text-transform:uppercase; letter-spacing:0.04em; color:#6B6A60; font-weight:700; padding:0.5rem 0.625rem; border-bottom:3px solid var(--ink); white-space:nowrap;}
        td{padding:0.625rem; border-bottom:2px solid #E5E2D6; color:#2B2A26; vertical-align:middle;}
        tr:last-child td{border-bottom:none;}
        tr.nb-row:hover{background:#F5F3EA; cursor:pointer;}
        td.strong{color:var(--ink); font-weight:700;}

        .nb-badge{display:inline-flex; align-items:center; gap:0.3125rem; font-size:0.656rem; font-weight:700; padding:0.25rem 0.625rem; border:2px solid; text-transform:uppercase; letter-spacing:0.02em; font-family:'Space Grotesk',sans-serif; white-space:nowrap;}
        .nb-tone-ok{background:var(--ok-bg); color:var(--ok-ink); border-color:var(--ok-line);}
        .nb-tone-bad{background:var(--bad-bg); color:var(--bad-ink); border-color:var(--bad-line);}
        .nb-tone-warn{background:var(--warn-bg); color:var(--warn-ink); border-color:var(--warn-line);}
        .nb-tone-pend{background:var(--pend-bg); color:var(--pend-ink); border-color:var(--pend-line);}
        .nb-tone-acc{background:var(--acc-bg); color:var(--acc-ink); border-color:var(--acc-line);}
        .nb-stamp{box-shadow:2px 2px 0 currentColor; transform:rotate(-2deg);}

        .nb-btn{font-family:'Space Grotesk',sans-serif; font-size:0.781rem; font-weight:700; padding:0.55rem 1rem; border:2.5px solid var(--ink); background:var(--paper); color:var(--ink); cursor:pointer; box-shadow:4px 4px 0 var(--ink); transition:transform .05s, box-shadow .05s; min-height:2.4rem;}
        .nb-btn:hover{transform:translate(-1px,-1px); box-shadow:5px 5px 0 var(--ink);}
        .nb-btn:active{transform:translate(3px,3px); box-shadow:1px 1px 0 var(--ink);}
        .nb-btn.primary{background:var(--accent); color:#fff;}
        .nb-btn.danger{background:var(--pink); color:#fff;}
        .nb-btn.small{padding:0.375rem 0.7rem; font-size:0.6875rem; box-shadow:3px 3px 0 var(--ink);}
        .nb-btn:disabled{opacity:0.45; cursor:not-allowed; transform:none; box-shadow:4px 4px 0 var(--ink);}
        .nb-btn-row{display:flex; gap:0.625rem; margin-top:1rem; flex-wrap:wrap; align-items:center;}

        .nb-field{margin-bottom:1rem;}
        .nb-field label{display:block; font-size:0.75rem; font-weight:700; margin-bottom:0.375rem; font-family:'Space Grotesk',sans-serif;}
        .nb-field .nb-help{font-size:0.6875rem; color:#8A8878; margin-top:0.3125rem;}
        .nb-field select, .nb-field input[type=text], .nb-field input[type=password]{
          width:100%; min-width:0; padding:0.625rem 0.7rem; font-size:0.781rem; border:2.5px solid var(--ink); background:#FCFBF6; color:var(--ink); font-family:'JetBrains Mono',monospace;
        }
        .nb-field select:focus, .nb-field input:focus{outline:3px solid var(--accent); outline-offset:1px;}
        .nb-check{display:flex; align-items:flex-start; gap:0.625rem; font-size:0.781rem; padding:0.75rem; border:2.5px solid var(--ink); background:#FCFBF6;}
        .nb-check input{margin-top:0.125rem; width:1rem; height:1rem; accent-color:var(--accent); flex:0 0 auto;}
        .nb-error{font-size:0.75rem; font-weight:700; color:var(--bad-ink); background:var(--bad-bg); border:2px solid var(--bad-line); padding:0.5rem 0.7rem; margin-top:0.25rem;}

        .nb-callout{border:2.5px dashed var(--ink); padding:0.7rem 0.875rem; font-size:0.72rem; color:#4A4940; background:repeating-linear-gradient(135deg,#FCFBF6,#FCFBF6 7px,#F0EDE2 7px,#F0EDE2 14px); overflow-wrap:anywhere;}
        .nb-callout b{color:var(--ink);}

        .nb-pipeline{display:flex; align-items:flex-start; gap:0; margin:0.5rem 0 0.125rem; overflow-x:auto; padding-bottom:0.25rem;}
        .nb-pstep{flex:1 0 min(7rem,45vw); text-align:center; position:relative; padding:0 0.25rem;}
        .nb-pstep-circle{width:1.875rem; aspect-ratio:1; border:2.5px solid var(--ink); background:var(--paper); display:flex; align-items:center; justify-content:center; font-size:0.75rem; font-weight:700; margin:0 auto 0.45rem; color:var(--ink); font-family:'Space Grotesk',sans-serif;}
        .nb-pstep-done .nb-pstep-circle{background:var(--ok-line); border-color:var(--ink); color:#fff;}
        .nb-pstep-current .nb-pstep-circle{background:var(--accent); border-color:var(--ink); color:#fff; box-shadow:3px 3px 0 var(--ink);}
        .nb-pstep-bad .nb-pstep-circle{background:var(--bad-line); border-color:var(--ink); color:#fff;}
        .nb-pstep-label{font-size:0.656rem; color:var(--ink); font-weight:700; font-family:'Space Grotesk',sans-serif;}
        .nb-pstep-line{position:absolute; top:0.875rem; left:-50%; width:100%; height:3px; background:var(--ink); z-index:-1;}
        .nb-pstep:first-child .nb-pstep-line{display:none;}
        .nb-pstep-done .nb-pstep-line, .nb-pstep-current .nb-pstep-line, .nb-pstep-bad .nb-pstep-line{background:var(--ok-line);}

        .nb-json{border:2.5px solid var(--ink); margin-bottom:0.625rem; box-shadow:3px 3px 0 var(--ink); min-width:0;}
        .nb-json-head{display:flex; align-items:center; justify-content:space-between; width:100%; padding:0.625rem 0.8rem; background:#F0EDE2; font-size:0.75rem; font-weight:700; cursor:pointer; border:none; font-family:'Space Grotesk',sans-serif; color:var(--ink);}
        .nb-json.open .nb-chev{transform:rotate(180deg);}
        .nb-json-body{margin:0; padding:0.8rem; font-family:'JetBrains Mono',monospace; font-size:0.706rem; color:#2B2A26; background:#FCFBF6; line-height:1.6; border-top:2.5px solid var(--ink); white-space:pre-wrap; overflow-wrap:anywhere;}

        .nb-detail-row{display:flex; justify-content:space-between; gap:0.625rem; font-size:0.781rem; padding:0.56rem 0; border-bottom:2px solid #E5E2D6; min-width:0;}
        .nb-detail-row:last-child{border-bottom:none;}
        .nb-detail-row .k{color:#6B6A60; font-weight:600; min-width:0;}
        .nb-detail-row .v{color:var(--ink); font-weight:700; text-align:right; font-family:'JetBrains Mono',monospace; min-width:0; overflow-wrap:anywhere;}

        .nb-filter-row{display:flex; gap:0.56rem; margin-bottom:1rem; flex-wrap:wrap;}
        .nb-filter-row select, .nb-filter-row input{font-size:0.75rem; padding:0.5rem 0.625rem; border:2.5px solid var(--ink); background:#FCFBF6; font-family:'JetBrains Mono',monospace; min-width:min(100%,8rem);}
        .nb-search{display:flex; align-items:center; gap:0.375rem; border:2.5px solid var(--ink); background:#FCFBF6; padding:0 0.625rem; flex:1 1 14rem; min-width:min(100%,14rem);}
        .nb-search input{border:none; background:none; padding:0.5rem 0; min-width:0; width:100%;}
        .nb-search input:focus{outline:none;}

        .nb-stamp-card{background:#fff; border:3px solid var(--ink); box-shadow:calc(var(--shadow) * 0.75) calc(var(--shadow) * 0.75) 0 var(--ink); padding:var(--card-pad); min-width:0; overflow:auto;}

        @media (max-width:48rem){
          .nb-root{width:100%; border-width:0; box-shadow:none;}
          .nb-shell{grid-template-columns:1fr; min-height:100svh;}
          .nb-sidebar{border-right:0; border-bottom:3px solid var(--ink); padding:0.75rem;}
          .nb-brand{display:flex; align-items:center; gap:0.75rem; padding:0 0 0.75rem; margin-bottom:0.75rem;}
          .nb-brand-mark{margin-bottom:0;}
          .nb-brand-sub{font-size:0.625rem;}
          .nb-nav{display:flex; gap:0.5rem; overflow-x:auto; padding:0 0 0.25rem;}
          .nb-nav-item{width:auto; flex:0 0 auto; margin-bottom:0; box-shadow:none;}
          .nb-sidebar-footer{display:none;}
          .nb-main{padding:1rem;}
          .nb-grid-4{grid-template-columns:repeat(2,minmax(0,1fr));}
        }

        @media (max-width:34rem){
          .nb-grid-4{grid-template-columns:1fr;}
          .nb-card,.nb-stamp-card{padding:0.875rem;}
          .nb-detail-row{display:grid; grid-template-columns:1fr; gap:0.25rem;}
          .nb-detail-row .v{text-align:left;}
          .nb-btn{width:100%; justify-content:center;}
          .nb-filter-row select,.nb-search{flex:1 1 100%; width:100%;}
        }
      `}</style>

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
          <div className="nb-sidebar-footer"><span className="nb-dot" />API connected</div>
        </aside>

        <main className="nb-main">
          {screen === "dashboard" && (
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
                        const meta = STATE_META[j.job_state];
                        return (
                          <tr key={j.id} className="nb-row" onClick={() => goto("jobdetail", { jobId: j.id })}>
                            <td className="strong nb-mono">{j.target}</td>
                            <td><Badge tone={meta.tone}>{meta.label}</Badge></td>
                            <td>{j.final_status ? <Badge tone={j.final_status === "SUCCESS" ? "ok" : "bad"}>{j.final_status}</Badge> : <Badge tone="pend">—</Badge>}</td>
                            <td>{j.dry_run ? "Yes" : "No"}</td>
                            <td>{j.updated}</td>
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
                      {certs.slice(0, 4).map((c) => (
                        <tr key={c.id} className="nb-row" onClick={() => goto("certificates", { certId: c.id })}>
                          <td className="nb-mono">{c.id}</td>
                          <td><Badge tone={c.final_status === "SUCCESS" ? "ok" : "bad"}>{c.final_status}</Badge></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  <div className="nb-btn-row"><button className="nb-btn small" onClick={() => goto("certificates")}>View all certificates</button></div>
                </div>
              </div>
            </>
          )}

          {screen === "assets" && (
            <>
              <div className="nb-crumbs">Assets</div>
              <h1 className="nb-h1 nb-heading">Asset inventory</h1>
              <p className="nb-sub">Read-only inventory. System-associated devices are blocked from destructive actions.</p>

              <div className="nb-grid-2">
                <div className="nb-card">
                  <div className="nb-filter-row">
                    <select value={assetType} onChange={(e) => setAssetType(e.target.value)}>
                      {["All", "HDD", "SSD", "NVMe"].map((o) => <option key={o}>{o}</option>)}
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
                    <thead><tr><th>Device path</th><th>Model</th><th>Type</th><th>Mounted</th><th>Flags</th></tr></thead>
                    <tbody>
                      {filteredAssets.map((a) => (
                        <tr key={a.id} className="nb-row" style={a.is_system_device ? { background: "#FBEDEA" } : {}} onClick={() => setSelectedAssetId(a.id)}>
                          <td className="strong nb-mono">{a.device_path}</td>
                          <td>{a.model}</td>
                          <td>{a.device_type}</td>
                          <td>{a.mounted ? "Yes" : "No"}</td>
                          <td>{a.is_system_device ? <Badge tone="bad">System device</Badge> : a.mounted_partitions.length > 1 ? <Badge tone="warn">{a.mounted_partitions.length} partitions</Badge> : "—"}</td>
                        </tr>
                      ))}
                      {filteredAssets.length === 0 && <tr><td colSpan={5} style={{ textAlign: "center", color: "#8A8878" }}>No assets match these filters.</td></tr>}
                    </tbody>
                  </table>
                </div>

                <div className="nb-card">
                  <div className="nb-section-title">Asset detail <span className="nb-hint">read-only</span></div>
                  <div className="nb-detail-row"><div className="k">device_path</div><div className="v">{selectedAsset.device_path}</div></div>
                  <div className="nb-detail-row"><div className="k">device_type</div><div className="v">{selectedAsset.device_type}</div></div>
                  <div className="nb-detail-row"><div className="k">serial_number</div><div className="v">{selectedAsset.serial_number}</div></div>
                  <div className="nb-detail-row"><div className="k">is_system_device</div><div className="v">{String(selectedAsset.is_system_device)}</div></div>
                  <div className="nb-detail-row"><div className="k">mounted</div><div className="v">{String(selectedAsset.mounted)}</div></div>
                  <div className="nb-detail-row"><div className="k">mounted_partitions</div><div className="v">{selectedAsset.mounted_partitions.join(", ") || "—"}</div></div>
                  {selectedAsset.is_system_device && (
                    <div className="nb-callout" style={{ marginTop: 12 }}><b>Blocked:</b> system-associated device. Destructive jobs cannot target this asset.</div>
                  )}
                </div>
              </div>
            </>
          )}

          {screen === "jobs" && (
            <>
              <div className="nb-crumbs">Jobs</div>
              <h1 className="nb-h1 nb-heading">Jobs</h1>
              <p className="nb-sub">Create a sanitization job and monitor existing ones.</p>

              <div className="nb-grid-2">
                <div className="nb-card">
                  <div className="nb-section-title">Job queue</div>
                  <div className="nb-filter-row">
                    <select value={jobStateFilter} onChange={(e) => setJobStateFilter(e.target.value)}>
                      {["All", ...Object.keys(STATE_META)].map((o) => <option key={o}>{o}</option>)}
                    </select>
                  </div>
                  <table>
                    <thead><tr><th>Target</th><th>Pathway</th><th>Job state</th><th>Final status</th><th>Dry run</th></tr></thead>
                    <tbody>
                      {filteredJobs.map((j) => {
                        const meta = STATE_META[j.job_state];
                        return (
                          <tr key={j.id} className="nb-row" onClick={() => goto("jobdetail", { jobId: j.id })}>
                            <td className="strong nb-mono">{j.target}</td>
                            <td>{j.pathway}</td>
                            <td><Badge tone={meta.tone}>{meta.label}</Badge></td>
                            <td>{j.final_status ? <Badge tone={j.final_status === "SUCCESS" ? "ok" : "bad"}>{j.final_status}</Badge> : <Badge tone="pend">—</Badge>}</td>
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
                      <select value={form.target} onChange={(e) => setForm({ ...form, target: e.target.value })}>
                        {assets.filter((a) => !a.is_system_device).map((a) => (
                          <option key={a.id} value={a.device_path}>{a.device_path} — {a.model} ({a.device_type})</option>
                        ))}
                      </select>
                    </div>
                    <div className="nb-field">
                      <label>ATA password <span className="nb-hint">only applies to ATA secure erase</span></label>
                      <input type="password" placeholder="Optional" value={form.ataPassword} onChange={(e) => setForm({ ...form, ataPassword: e.target.value })} />
                    </div>
                    <div className="nb-field" style={{ marginBottom: 12 }}>
                      <div className="nb-check">
                        <input type="checkbox" checked={form.dryRun} onChange={(e) => setForm({ ...form, dryRun: e.target.checked })} />
                        <div>Dry run — plan only, no destructive action is taken.</div>
                      </div>
                    </div>
                    <div className="nb-field" style={{ marginBottom: 8 }}>
                      <div className="nb-check">
                        <input type="checkbox" checked={form.authorized} onChange={(e) => setForm({ ...form, authorized: e.target.checked })} />
                        <div><b>I authorize this destructive operation.</b> Required before submission unless dry run is checked.</div>
                      </div>
                    </div>
                    {formError && <div className="nb-error">{formError}</div>}
                    <div className="nb-btn-row">
                      <button type="submit" className="nb-btn primary">Submit job</button>
                      <button type="button" className="nb-btn" onClick={() => setForm({ target: assets[0].device_path, ataPassword: "", dryRun: true, authorized: false })}>Reset</button>
                    </div>
                  </form>
                </div>
              </div>
            </>
          )}

          {screen === "jobdetail" && selectedJob && (
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
              </div>

              <div className="nb-grid-2">
                <div>
                  <div className="nb-section-title" style={{ marginTop: 4 }}>Payloads <span className="nb-hint">expandable, not raw blobs</span></div>
                  <JsonPanel title="execution_json" json={selectedJob.execution_json} defaultOpen />
                  <JsonPanel title="verification_json" json={selectedJob.verification_json} />
                  <JsonPanel title="evidence_json" json={selectedJob.evidence_json} />
                  {selectedJob.certificate && (
                    <div className="nb-stamp-card" style={{ marginTop: 14 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
                        <ShieldCheck size={18} aria-hidden="true" />
                        <span className="nb-heading" style={{ fontSize: 13 }}>Certificate issued</span>
                      </div>
                      <div className="nb-detail-row"><div className="k">certificate_id</div><div className="v">{selectedJob.certificate.id}</div></div>
                      <div className="nb-detail-row"><div className="k">certificate_hash</div><div className="v">{selectedJob.certificate.hash}</div></div>
                      <div className="nb-detail-row"><div className="k">standard</div><div className="v">{selectedJob.certificate.standard}</div></div>
                    </div>
                  )}
                </div>

                <div>
                  <div className="nb-section-title" style={{ marginTop: 4 }}>Audit log entries <span className="nb-hint">this job</span></div>
                  <div className="nb-card" style={{ padding: 0 }}>
                    <table>
                      <thead><tr><th>Action</th><th>Actor</th><th>At</th></tr></thead>
                      <tbody>
                        {selectedJob.audit.map((a, i) => (
                          <tr key={i}><td>{a.action}</td><td>{a.actor}</td><td className="nb-mono">{a.at}</td></tr>
                        ))}
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

          {screen === "certificates" && (
            <>
              <div className="nb-crumbs">Certificates</div>
              <h1 className="nb-h1 nb-heading">Certificates</h1>
              <p className="nb-sub">Certificate index and detail, with hash and sanitization claim.</p>

              <div className="nb-grid-2">
                <div className="nb-card">
                  <table>
                    <thead><tr><th>Certificate</th><th>Target</th><th>Outcome</th><th>Claim</th></tr></thead>
                    <tbody>
                      {certs.map((c) => (
                        <tr key={c.id} className="nb-row" onClick={() => setSelectedCertId(c.id)}>
                          <td className="nb-mono">{c.id}</td>
                          <td className="nb-mono">{c.target}</td>
                          <td><Badge tone={c.final_status === "SUCCESS" ? "ok" : "bad"}>{c.final_status}</Badge></td>
                          <td>{c.claim ? "Successful" : "Not claimed"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="nb-stamp-card">
                  <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                    <ShieldCheck size={20} aria-hidden="true" />
                    <span className="nb-heading" style={{ fontSize: 14 }}>Certificate detail</span>
                  </div>
                  <div className="nb-detail-row"><div className="k">certificate_id</div><div className="v">{selectedCert.id}</div></div>
                  <div className="nb-detail-row"><div className="k">job_id</div><div className="v">{selectedCert.job_id}</div></div>
                  <div className="nb-detail-row"><div className="k">target</div><div className="v">{selectedCert.target}</div></div>
                  <div className="nb-detail-row"><div className="k">final_status</div><div className="v"><Badge tone={selectedCert.final_status === "SUCCESS" ? "ok" : "bad"} stamp>{selectedCert.final_status}</Badge></div></div>
                  <div className="nb-detail-row"><div className="k">successful_sanitization_claim</div><div className="v">{String(selectedCert.claim)}</div></div>
                  <div className="nb-detail-row"><div className="k">certificate_hash</div><div className="v">{selectedCert.hash}</div></div>
                  <JsonPanel title="certificate_json" json={'{\n  "standard": "' + selectedCert.standard + '",\n  "issued_at": "' + selectedCert.issued + '"\n}'} />
                </div>
              </div>
            </>
          )}

          {screen === "auditlogs" && (
            <>
              <div className="nb-crumbs">Audit logs</div>
              <h1 className="nb-h1 nb-heading">Audit trail</h1>
              <p className="nb-sub">Request and response entries with actor metadata and timestamps.</p>

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
                  <thead><tr><th>Action</th><th>Actor</th><th>Request</th><th>Response</th><th>At</th></tr></thead>
                  <tbody>
                    {filteredAuditLogs.map((l, i) => (
                      <tr key={i} className="nb-row">
                        <td className="strong">{l.action}</td>
                        <td>{l.actor}</td>
                        <td className="nb-mono">{l.request}</td>
                        <td className="nb-mono">{l.response}</td>
                        <td className="nb-mono">{l.at}</td>
                      </tr>
                    ))}
                    {filteredAuditLogs.length === 0 && <tr><td colSpan={5} style={{ textAlign: "center", color: "#8A8878" }}>No entries match these filters.</td></tr>}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {screen === "settings" && (
            <>
              <div className="nb-crumbs">Settings</div>
              <h1 className="nb-h1 nb-heading">Settings</h1>
              <p className="nb-sub">API base URL and optional authentication.</p>

              <div className="nb-card" style={{ maxWidth: 460 }}>
                <div className="nb-field">
                  <label>VYPER_API_BASE_URL</label>
                  <input type="text" value={apiUrl} onChange={(e) => setApiUrl(e.target.value)} />
                </div>
                <div className="nb-field">
                  <label>X-VYPER-API-Key</label>
                  <input type="password" placeholder="Optional — only if backend enforces auth" value={apiKey} onChange={(e) => setApiKey(e.target.value)} />
                  <div className="nb-help">Sent as a request header when set.</div>
                </div>
                <div className="nb-btn-row">
                  <button className="nb-btn primary" type="button" onClick={() => { setSavedMsg("Settings saved."); setTimeout(() => setSavedMsg(""), 2200); }}>Save settings</button>
                  {savedMsg && <Badge tone="ok">{savedMsg}</Badge>}
                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
}
