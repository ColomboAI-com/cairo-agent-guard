import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://cairo.sh"),
  title: "Cairo Agent Guard — Every AI Agent Needs an Identity",
  description:
    "Identity, containment, certification, and platform defense for trustworthy autonomous systems.",
  alternates: {
    canonical: "/AgentGuard",
  },
  icons: {
    icon: "/AgentGuard/cairo-logo.svg",
    shortcut: "/AgentGuard/cairo-logo.svg",
  },
  openGraph: {
    type: "website",
    url: "https://cairo.sh/AgentGuard",
    title: "Cairo Agent Guard — Every AI Agent Needs an Identity",
    description:
      "Identity. Containment. Certification. Platform defense.",
    images: [
      { url: "/AgentGuard/agentguard-launch-og.png", width: 1792, height: 896 },
      { url: "/AgentGuard/og.png", width: 1792, height: 896 },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Cairo Agent Guard",
    description: "Every AI agent needs an identity—and an enforceable security boundary.",
    images: ["/AgentGuard/agentguard-launch-og.png"],
  },
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
