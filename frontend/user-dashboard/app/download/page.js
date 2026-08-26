"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { createApiClient, formatApiError, getDefaultApiBaseUrl } from "../../lib/api.mjs";
import { selectLinuxX64Release } from "../../lib/downloads.mjs";
import DownloadsContent from "../downloads-content";

export default function DownloadPage() {
  const client = useMemo(() => createApiClient({ baseUrl: getDefaultApiBaseUrl() }), []);
  const [release, setRelease] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    client.listDownloads()
      .then((items) => active && setRelease(selectLinuxX64Release(items)))
      .catch((reason) => active && setError(formatApiError(reason)));
    return () => { active = false; };
  }, [client]);

  return (
    <main style={{ maxWidth: 900, margin: "40px auto", padding: 24, fontFamily: "system-ui", color: "#14141A" }}>
      <Link href="/" style={{ color: "#3A5CFF", fontWeight: 700 }}>← VYPER dashboard</Link>
      <DownloadsContent apiBase={getDefaultApiBaseUrl()} error={error} release={release} />
    </main>
  );
}
