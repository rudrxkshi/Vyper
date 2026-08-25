import "./globals.css";

export const metadata = {
  title: "VYPER Sanitization Console",
  description: "Authenticated VYPER storage sanitization operations and evidence console",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" className="h-full antialiased">
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
