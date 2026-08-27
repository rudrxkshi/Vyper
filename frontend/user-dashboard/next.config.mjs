const localEmbeddedExport = process.env.NEXT_PUBLIC_VYPER_MODE === "local";

/** @type {import('next').NextConfig} */
const nextConfig = {
  output: "export",
  trailingSlash: true,
  // Tauri's custom protocol does not provide an HTTP origin root for /_next.
  // Both exported routes are at most one directory deep, so ../_next resolves
  // to the shared export assets from index.html and download/index.html alike.
  assetPrefix: localEmbeddedExport ? ".." : undefined,
};

export default nextConfig;
