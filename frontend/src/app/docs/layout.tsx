import { Instrument_Serif, Outfit, Fira_Code } from "next/font/google";
import type { Metadata } from "next";

const serif = Instrument_Serif({
  subsets: ["latin"],
  weight: "400",
  style: ["normal", "italic"],
  variable: "--font-serif",
  display: "swap",
});

const sans = Outfit({
  subsets: ["latin"],
  variable: "--font-sans",
  display: "swap",
});

const mono = Fira_Code({
  subsets: ["latin"],
  variable: "--font-mono",
  display: "swap",
});

export const metadata: Metadata = {
  title: "Documentation — Janus Security",
  description:
    "Developer documentation for Janus, the autonomous security layer for AI agents. SDK quickstart, API reference, configuration, architecture.",
};

export default function DocsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <div className={`${serif.variable} ${sans.variable} ${mono.variable}`}>
      {children}
    </div>
  );
}
