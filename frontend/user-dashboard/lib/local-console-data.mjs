function requireArray(value, endpoint) {
  if (!Array.isArray(value)) {
    throw new TypeError(`Local ${endpoint} response must be a JSON array.`);
  }
  return value;
}

export async function loadLocalConsoleData(apiClient) {
  const [devices, jobs, certificates, auditLogs, remoteRequests, syncStatus] = await Promise.all([
    apiClient.listDevices(),
    apiClient.listJobs(),
    apiClient.listCertificates(),
    apiClient.listAuditLogs(),
    apiClient.listRemoteJobs(),
    apiClient.getSyncStatus(),
  ]);
  return {
    devices: requireArray(devices, "devices"),
    jobs: requireArray(jobs, "jobs"),
    certificates: requireArray(certificates, "certificates"),
    auditLogs: requireArray(auditLogs, "audit-logs"),
    remoteRequests: requireArray(remoteRequests, "remote-jobs"),
    syncStatus,
  };
}
