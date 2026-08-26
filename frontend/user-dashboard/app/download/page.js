"use client";

import { useEffect, useMemo, useState } from "react";
import { Download, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { createApiClient, formatApiError, getDefaultApiBaseUrl } from "../../lib/api.mjs";

function formatBytes(value) {
  if (!Number.isFinite(value)) return "Unknown";
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

export default function DownloadPage() {
  const client = useMemo(() => createApiClient({ baseUrl: getDefaultApiBaseUrl() }), []);
  const [release, setRelease] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    client.listDownloads()
      .then((items) => active && setRelease(items.find((item) => item.platform === "linux" && item.architecture === "x86_64") || null))
      .catch((reason) => active && setError(formatApiError(reason)));
    return () => { active = false; };
  }, [client]);

  const apiBase = getDefaultApiBaseUrl();
  const downloadUrl = release ? `${apiBase}${release.download_url}` : null;

  return (
    <main style={{ maxWidth: 900, margin: "40px auto", padding: 24, fontFamily: "system-ui", color: "#14141A" }}>
      <Link href="/" style={{ color: "#3A5CFF", fontWeight: 700 }}>← VYPER dashboard</Link>
      <h1 style={{ fontSize: 42, marginBottom: 8 }}>Download VYPER Local Console</h1>
      <p>Install the loopback-only local console and outbound VYPER agent without cloning the repository.</p>
      {error && <p role="alert">Release metadata unavailable: {error}</p>}
      {release ? (
        <section style={{ border: "3px solid #14141A", boxShadow: "8px 8px 0 #14141A", padding: 24, marginTop: 28 }}>
          <h2>Linux x86_64</h2>
          <dl>
            <dt>Version</dt><dd>{release.version}</dd>
            <dt>Release date</dt><dd>{release.release_date}</dd>
            <dt>File size</dt><dd>{formatBytes(release.size_bytes)}</dd>
            <dt>SHA-256</dt><dd style={{ fontFamily: "monospace", overflowWrap: "anywhere" }}>{release.sha256}</dd>
          </dl>
          <a href={downloadUrl} style={{ display: "inline-flex", gap: 8, padding: "12px 18px", background: "#3A5CFF", color: "white", fontWeight: 700 }}>
            <Download size={18} /> Download {release.filename}
          </a>
          <p><ShieldCheck size={16} style={{ verticalAlign: "middle" }} /> Checksum integrity only; package signing is a future production requirement.</p>
          <pre style={{ background: "#F0EDE2", padding: 16, overflowX: "auto" }}>sha256sum -c checksums.txt{"\n"}sudo ./install.sh{"\n"}sudo vyper enroll{"\n"}vyper open</pre>
        </section>
      ) : !error && <p>No Linux release is currently published.</p>}
      <section style={{ marginTop: 32 }}>
        <h2>Other platforms</h2>
        <p>Windows — Coming soon (unavailable)</p>
        <p>macOS — Coming soon (unavailable)</p>
      </section>
    </main>
  );
}
