import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://cairo.sh"),
  title: "Cairo Agent Guard — Security for the Agentic Internet",
  description:
    "Agent Identity, Agent Guard Protocol, Runtime, and Agent Guard Edge for trustworthy autonomous systems.",
  icons: {
    icon: "/AgentGuard/cairo-logo.svg",
    shortcut: "/AgentGuard/cairo-logo.svg",
  },
  openGraph: {
    type: "website",
    url: "https://cairo.sh/AgentGuard",
    title: "Cairo Agent Guard — Security for the Agentic Internet",
    description:
      "Know the agent. Bound its authority. Enforce at the edge.",
    images: [{ url: "/AgentGuard/og.png", width: 1792, height: 896 }],
  },
  twitter: {
    card: "summary_large_image",
    title: "Cairo Agent Guard",
    description: "The security layer for the Agentic Internet.",
    images: ["/AgentGuard/og.png"],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
