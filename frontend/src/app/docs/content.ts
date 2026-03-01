/**
 * Documentation content registry.
 *
 * Each entry maps a URL slug to a doc section with its markdown source
 * loaded at build time from the /docs directory.
 */

import fs from "fs";
import path from "path";

export interface DocSection {
  slug: string;
  title: string;
  shortTitle: string;
  description: string;
  category: "getting-started" | "reference" | "guides";
  file: string;
  order: number;
}

export const DOC_SECTIONS: DocSection[] = [
  {
    slug: "quickstart",
    title: "SDK Quickstart",
    shortTitle: "Quickstart",
    description: "Integrate Janus into your Python agent",
    category: "getting-started",
    file: "sdk-quickstart.md",
    order: 0,
  },
  {
    slug: "mcp-proxy",
    title: "MCP Proxy Guide",
    shortTitle: "MCP Proxy",
    description: "Protect MCP clients like Claude Desktop",
    category: "getting-started",
    file: "mcp-proxy-guide.md",
    order: 1,
  },
  {
    slug: "deployment",
    title: "Deployment Guide",
    shortTitle: "Deployment",
    description: "Self-host Janus for production use",
    category: "getting-started",
    file: "deployment.md",
    order: 2,
  },
  {
    slug: "architecture",
    title: "Architecture Overview",
    shortTitle: "Architecture",
    description: "System design, pipeline, and data flow",
    category: "reference",
    file: "architecture.md",
    order: 3,
  },
  {
    slug: "api-reference",
    title: "REST API Reference",
    shortTitle: "API Reference",
    description: "All HTTP endpoints and schemas",
    category: "reference",
    file: "api-reference.md",
    order: 4,
  },
  {
    slug: "configuration",
    title: "Configuration Reference",
    shortTitle: "Configuration",
    description: "TOML config, env vars, CLI commands",
    category: "reference",
    file: "configuration.md",
    order: 5,
  },
];

const DOCS_DIR = path.join(process.cwd(), "..", "docs");

export function getDocContent(slug: string): string | null {
  const section = DOC_SECTIONS.find((s) => s.slug === slug);
  if (!section) return null;

  const filePath = path.join(DOCS_DIR, section.file);
  try {
    return fs.readFileSync(filePath, "utf-8");
  } catch {
    return null;
  }
}

export function getAllSlugs(): string[] {
  return DOC_SECTIONS.map((s) => s.slug);
}

export function getSectionsByCategory() {
  const categories = {
    "getting-started": { label: "Getting Started", sections: [] as DocSection[] },
    reference: { label: "Reference", sections: [] as DocSection[] },
    guides: { label: "Guides", sections: [] as DocSection[] },
  };

  for (const section of DOC_SECTIONS) {
    categories[section.category].sections.push(section);
  }

  return Object.entries(categories)
    .filter(([, cat]) => cat.sections.length > 0)
    .map(([key, cat]) => ({
      key,
      label: cat.label,
      sections: cat.sections.sort((a, b) => a.order - b.order),
    }));
}
