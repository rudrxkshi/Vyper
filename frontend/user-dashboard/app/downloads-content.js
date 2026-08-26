import { Download, ShieldCheck } from "lucide-react";
import { releaseDownloadUrl } from "../lib/downloads.mjs";

export default function DownloadsContent({ apiBase, error, release, dashboard = false }) {
  const downloadUrl = releaseDownloadUrl(apiBase, release);
  const cardProps = dashboard
    ? { className: "nb-card" }
    : { style: { border: "3px solid #14141A", boxShadow: "8px 8px 0 #14141A", padding: 24, marginTop: 28 } };

  return (
    <>
      {dashboard ? (
        <>
          <div className="nb-crumbs">Central / Downloads</div>
          <h1 className="nb-h1 nb-heading">Downloads</h1>
          <p className="nb-sub">Download published VYPER release artifacts and verify their integrity.</p>
        </>
      ) : (
        <>
          <h1 style={{ fontSize: 42, marginBottom: 8 }}>Download VYPER Local Console</h1>
          <p>Install the loopback-only local console and outbound VYPER agent without cloning the repository.</p>
        </>
      )}
      {error && <p role="alert">Release metadata unavailable: {error}</p>}
      {release ? (
        <section {...cardProps}>
          {dashboard && <div className="nb-section-title">Linux x86_64 release</div>}
          {!dashboard && <h2>Linux x86_64</h2>}
          <table>
            <tbody>
              <tr><th>Version</th><td>{release.version}</td></tr>
              <tr><th>Published</th><td>{release.release_date}</td></tr>
              <tr><th>File size</th><td>{formatBytes(release.size_bytes)}</td></tr>
              <tr><th>SHA-256</th><td className="nb-mono" style={{ overflowWrap: "anywhere" }}>{release.sha256}</td></tr>
            </tbody>
          </table>
          <div className="nb-btn-row">
            <a className={dashboard ? "nb-btn primary" : undefined} href={downloadUrl} style={dashboard ? undefined : { display: "inline-flex", gap: 8, padding: "12px 18px", background: "#3A5CFF", color: "white", fontWeight: 700 }}>
              <Download size={18} /> Download {release.filename}
            </a>
          </div>
          <p><ShieldCheck size={16} style={{ verticalAlign: "middle" }} /> Checksum integrity only; package signing is a future production requirement.</p>
          <pre style={{ background: "#F0EDE2", padding: 16, overflowX: "auto" }}>sha256sum -c checksums.txt{"\n"}sudo ./install.sh{"\n"}sudo vyper enroll{"\n"}vyper open</pre>
        </section>
      ) : !error && <p>No Linux release is currently published.</p>}
      <section className={dashboard ? "nb-card" : undefined} style={dashboard ? undefined : { marginTop: 32 }}>
        <div className={dashboard ? "nb-section-title" : undefined}>{dashboard ? "Other platforms" : <h2>Other platforms</h2>}</div>
        <p>Windows — Coming soon (unavailable)</p>
        <p>macOS — Coming soon (unavailable)</p>
      </section>
    </>
  );
}

function formatBytes(value) {
  if (!Number.isFinite(value)) return "Unknown";
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}
