import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "NIDS | Network Intrusion Detection System",
  description:
    "Real-time network intrusion detection and classification dashboard powered by machine learning",
  icons: {
    icon: "data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'><text y='.9em' font-size='90'>🛡️</text></svg>",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="antialiased min-h-screen relative">
        <div className="relative z-10">{children}</div>
      </body>
    </html>
  );
}
