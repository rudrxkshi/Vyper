export function selectLinuxX64Release(items) {
  return items.find((item) => item.platform === "linux" && item.architecture === "x86_64") || null;
}

export function releaseDownloadUrl(apiBase, release) {
  return release ? `${apiBase}${release.download_url}` : null;
}
