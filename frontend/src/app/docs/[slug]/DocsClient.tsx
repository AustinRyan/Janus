"use client";

import { useState, useEffect, useRef, useCallback, type ReactNode } from "react";
import Link from "next/link";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeSlug from "rehype-slug";
import rehypeRaw from "rehype-raw";
import {
  Shield,
  Book,
  Code,
  Server,
  Layers,
  FileText,
  Settings,
  ChevronRight,
  Copy,
  Check,
  ArrowLeft,
  Menu,
  X,
  ExternalLink,
  Search,
  ChevronDown,
} from "lucide-react";

/* ═══════════════════════════════════════════════════════════════
   TYPES
   ═══════════════════════════════════════════════════════════════ */

interface DocSection {
  slug: string;
  title: string;
  shortTitle: string;
  description: string;
  category: string;
  file: string;
  order: number;
}

interface Category {
  key: string;
  label: string;
  sections: DocSection[];
}

interface TocEntry {
  id: string;
  text: string;
  level: number;
}

interface DocsClientProps {
  slug: string;
  content: string;
  section: DocSection;
  categories: Category[];
}

/* ═══════════════════════════════════════════════════════════════
   CONSTANTS
   ═══════════════════════════════════════════════════════════════ */

const SECTION_ICONS: Record<string, typeof Book> = {
  quickstart: Code,
  "mcp-proxy": Server,
  deployment: Layers,
  architecture: Layers,
  "api-reference": FileText,
  configuration: Settings,
};

/* ═══════════════════════════════════════════════════════════════
   TOC EXTRACTION
   ═══════════════════════════════════════════════════════════════ */

function extractToc(markdown: string): TocEntry[] {
  const entries: TocEntry[] = [];
  const lines = markdown.split("\n");
  const seenIds = new Map<string, number>();

  for (const line of lines) {
    const match = line.match(/^(#{2,3})\s+(.+)$/);
    if (match) {
      const level = match[1].length;
      const text = match[2]
        .replace(/\*\*(.+?)\*\*/g, "$1")
        .replace(/`(.+?)`/g, "$1")
        .replace(/\[(.+?)\]\(.+?\)/g, "$1");
      let id = text
        .toLowerCase()
        .replace(/[^\w\s-]/g, "")
        .replace(/\s+/g, "-")
        .replace(/-+/g, "-")
        .replace(/^-|-$/g, "");

      // Deduplicate: rehype-slug appends -1, -2 for duplicate headings
      const count = seenIds.get(id) ?? 0;
      seenIds.set(id, count + 1);
      if (count > 0) {
        id = `${id}-${count}`;
      }

      entries.push({ id, text, level });
    }
  }

  return entries;
}

/* ═══════════════════════════════════════════════════════════════
   CODE BLOCK
   ═══════════════════════════════════════════════════════════════ */

function extractText(node: ReactNode): string {
  if (typeof node === "string") return node;
  if (typeof node === "number") return String(node);
  if (!node) return "";
  if (Array.isArray(node)) return node.map(extractText).join("");
  if (typeof node === "object" && "props" in node) {
    return extractText((node as { props: { children?: ReactNode } }).props.children);
  }
  return "";
}

function isAsciiDiagram(text: string): boolean {
  const lines = text.split("\n").filter((l) => l.trim().length > 0);
  if (lines.length < 3) return false;
  let diagramChars = 0;
  for (const line of lines) {
    if (/[+|\\/>v^<].*[-|+]/.test(line) || /[-=]{3,}/.test(line) || /\+[-=]+\+/.test(line) || /--[>)]/.test(line)) {
      diagramChars++;
    }
  }
  return diagramChars / lines.length > 0.3;
}

function CodeBlock({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const codeRef = useRef<HTMLElement>(null);
  const lang = className?.replace("language-", "") || "";

  const textContent = extractText(children);
  const isDiagram = !lang && isAsciiDiagram(textContent);

  const copy = useCallback(() => {
    const text = codeRef.current?.textContent ?? "";
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, []);

  if (isDiagram) {
    return (
      <div className="doc-diagram group relative">
        <button
          onClick={copy}
          className="absolute right-3 top-3 z-10 flex h-7 w-7 items-center justify-center rounded-md border border-[#1e2233]/60 bg-[#080a11] text-[#636880] opacity-0 transition-all hover:border-[#5eead4]/40 hover:text-[#5eead4] group-hover:opacity-100"
          aria-label="Copy"
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
        </button>
        <pre className="doc-diagram-pre">
          <code ref={codeRef}>{children}</code>
        </pre>
      </div>
    );
  }

  return (
    <div className="doc-code-block group relative">
      {lang && (
        <div className="doc-code-lang">{lang}</div>
      )}
      <button
        onClick={copy}
        className="absolute right-3 top-3 z-10 flex h-7 w-7 items-center justify-center rounded-md border border-[#1e2233]/60 bg-[#0a0c13] text-[#636880] opacity-0 transition-all hover:border-[#5eead4]/40 hover:text-[#5eead4] group-hover:opacity-100"
        aria-label="Copy code"
      >
        {copied ? <Check size={12} /> : <Copy size={12} />}
      </button>
      <pre className="doc-pre">
        <code ref={codeRef} className={className}>
          {children}
        </code>
      </pre>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   SIDEBAR
   ═══════════════════════════════════════════════════════════════ */

function Sidebar({
  categories,
  currentSlug,
  onNavigate,
}: {
  categories: Category[];
  currentSlug: string;
  onNavigate?: () => void;
}) {
  return (
    <nav className="flex flex-col gap-6">
      {categories.map((cat) => (
        <div key={cat.key}>
          <h3 className="mb-2 px-3 text-[10px] font-bold uppercase tracking-[0.15em] text-[#4a4e63]">
            {cat.label}
          </h3>
          <ul className="flex flex-col gap-0.5">
            {cat.sections.map((sec) => {
              const active = sec.slug === currentSlug;
              const Icon = SECTION_ICONS[sec.slug] || Book;
              return (
                <li key={sec.slug}>
                  <Link
                    href={`/docs/${sec.slug}`}
                    onClick={onNavigate}
                    className={`group flex items-center gap-2.5 rounded-lg px-3 py-2 text-[13px] transition-all ${
                      active
                        ? "bg-[#5eead4]/8 text-[#5eead4] font-medium"
                        : "text-[#8b8fa3] hover:bg-[#ffffff]/[0.03] hover:text-[#c8cad4]"
                    }`}
                  >
                    <Icon
                      size={14}
                      className={`shrink-0 transition-colors ${
                        active
                          ? "text-[#5eead4]"
                          : "text-[#4a4e63] group-hover:text-[#636880]"
                      }`}
                    />
                    {sec.shortTitle}
                    {active && (
                      <div className="ml-auto h-1 w-1 rounded-full bg-[#5eead4] shadow-[0_0_4px_#5eead4]" />
                    )}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

/* ═══════════════════════════════════════════════════════════════
   TABLE OF CONTENTS
   ═══════════════════════════════════════════════════════════════ */

function TableOfContents({
  entries,
  activeId,
}: {
  entries: TocEntry[];
  activeId: string;
}) {
  if (entries.length === 0) return null;

  return (
    <nav className="flex flex-col gap-0.5">
      <h4 className="mb-2 text-[10px] font-bold uppercase tracking-[0.15em] text-[#4a4e63]">
        On this page
      </h4>
      {entries.map((entry) => {
        const active = entry.id === activeId;
        return (
          <a
            key={entry.id}
            href={`#${entry.id}`}
            className={`block truncate py-1 text-[12px] leading-snug transition-colors ${
              entry.level === 3 ? "pl-3" : ""
            } ${
              active
                ? "text-[#5eead4] font-medium"
                : "text-[#4a4e63] hover:text-[#8b8fa3]"
            }`}
          >
            {entry.text}
          </a>
        );
      })}
    </nav>
  );
}

/* ═══════════════════════════════════════════════════════════════
   SEARCH (lightweight client-side)
   ═══════════════════════════════════════════════════════════════ */

function SearchOverlay({
  categories,
  onClose,
}: {
  categories: Category[];
  onClose: () => void;
}) {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    inputRef.current?.focus();
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onClose]);

  const allSections = categories.flatMap((c) => c.sections);
  const filtered = query
    ? allSections.filter(
        (s) =>
          s.title.toLowerCase().includes(query.toLowerCase()) ||
          s.description.toLowerCase().includes(query.toLowerCase())
      )
    : allSections;

  return (
    <div
      className="fixed inset-0 z-[100] flex items-start justify-center bg-black/60 pt-[15vh] backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="w-full max-w-lg overflow-hidden rounded-xl border border-[#1e2233] bg-[#0a0c13] shadow-2xl shadow-black/40"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center gap-3 border-b border-[#1e2233] px-4 py-3">
          <Search size={15} className="shrink-0 text-[#4a4e63]" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search documentation..."
            className="flex-1 bg-transparent text-[14px] text-[#e4e7ef] placeholder:text-[#4a4e63] outline-none"
            style={{ fontFamily: "var(--font-sans)" }}
          />
          <kbd className="rounded border border-[#1e2233] bg-[#0e1018] px-1.5 py-0.5 text-[10px] text-[#4a4e63]">
            ESC
          </kbd>
        </div>
        <div className="max-h-[320px] overflow-y-auto p-2">
          {filtered.length === 0 && (
            <p className="px-3 py-6 text-center text-[13px] text-[#4a4e63]">
              No results found
            </p>
          )}
          {filtered.map((sec) => {
            const Icon = SECTION_ICONS[sec.slug] || Book;
            return (
              <Link
                key={sec.slug}
                href={`/docs/${sec.slug}`}
                onClick={onClose}
                className="flex items-center gap-3 rounded-lg px-3 py-2.5 text-[13px] transition-colors hover:bg-[#ffffff]/[0.04]"
              >
                <Icon size={14} className="shrink-0 text-[#636880]" />
                <div className="min-w-0 flex-1">
                  <div className="text-[#e4e7ef]">{sec.title}</div>
                  <div className="truncate text-[11px] text-[#4a4e63]">
                    {sec.description}
                  </div>
                </div>
                <ChevronRight size={12} className="shrink-0 text-[#2a2e40]" />
              </Link>
            );
          })}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   MAIN DOC CLIENT
   ═══════════════════════════════════════════════════════════════ */

export function DocsClient({
  slug,
  content,
  section,
  categories,
}: DocsClientProps) {
  const [mobileMenu, setMobileMenu] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [activeHeading, setActiveHeading] = useState("");
  const [tocCollapsed, setTocCollapsed] = useState(false);

  const tocEntries = extractToc(content);

  // Track active heading via intersection observer
  useEffect(() => {
    const headings = document.querySelectorAll(
      ".doc-content h2[id], .doc-content h3[id]"
    );
    if (headings.length === 0) return;

    const observer = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActiveHeading(entry.target.id);
          }
        }
      },
      { rootMargin: "-80px 0px -70% 0px", threshold: 0 }
    );

    headings.forEach((h) => observer.observe(h));
    return () => observer.disconnect();
  }, [content]);

  // Keyboard shortcut for search
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen(true);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  return (
    <div
      className="min-h-screen bg-[#06080e] text-[#c8cad4]"
      style={{ fontFamily: "var(--font-sans)" }}
    >
      {/* ── TOP BAR ── */}
      <header className="fixed top-0 left-0 right-0 z-50 border-b border-[#1e2233]/60 bg-[#06080e]/90 backdrop-blur-xl">
        <div className="mx-auto flex h-14 max-w-[1440px] items-center gap-4 px-4 lg:px-6">
          {/* Logo */}
          <Link
            href="/landing"
            className="flex shrink-0 items-center gap-2"
          >
            <div className="flex h-7 w-7 items-center justify-center rounded-md bg-[#5eead4]/10">
              <Shield size={14} className="text-[#5eead4]" />
            </div>
            <span
              className="text-[15px] font-semibold tracking-tight text-[#e4e7ef]"
              style={{ fontFamily: "var(--font-sans)" }}
            >
              Janus
            </span>
          </Link>

          <div className="mx-2 h-4 w-px bg-[#1e2233]" />

          <Link
            href="/docs/quickstart"
            className="text-[13px] font-medium text-[#636880] transition-colors hover:text-[#e4e7ef]"
          >
            Docs
          </Link>

          {/* Search */}
          <button
            onClick={() => setSearchOpen(true)}
            className="ml-auto flex items-center gap-2 rounded-lg border border-[#1e2233]/60 bg-[#0a0c13] px-3 py-1.5 text-[12px] text-[#4a4e63] transition-all hover:border-[#5eead4]/20 hover:text-[#636880] sm:w-56"
          >
            <Search size={13} />
            <span className="hidden sm:inline">Search docs...</span>
            <kbd className="ml-auto hidden rounded border border-[#1e2233] bg-[#0e1018] px-1 py-0.5 text-[10px] sm:inline">
              ⌘K
            </kbd>
          </button>

          {/* GitHub link */}
          <a
            href="https://github.com/AustinRyan/project-sentinel"
            target="_blank"
            rel="noopener noreferrer"
            className="hidden items-center gap-1.5 text-[12px] text-[#636880] transition-colors hover:text-[#e4e7ef] sm:flex"
          >
            GitHub
            <ExternalLink size={11} />
          </a>

          {/* Mobile menu button */}
          <button
            className="flex h-8 w-8 items-center justify-center rounded-md border border-[#1e2233] lg:hidden"
            onClick={() => setMobileMenu(!mobileMenu)}
            aria-label="Toggle navigation"
          >
            {mobileMenu ? (
              <X size={14} className="text-[#636880]" />
            ) : (
              <Menu size={14} className="text-[#636880]" />
            )}
          </button>
        </div>
      </header>

      {/* ── MOBILE SIDEBAR ── */}
      {mobileMenu && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div
            className="absolute inset-0 bg-black/50 backdrop-blur-sm"
            onClick={() => setMobileMenu(false)}
          />
          <div className="absolute left-0 top-14 bottom-0 w-72 overflow-y-auto border-r border-[#1e2233] bg-[#06080e] p-5">
            <Sidebar
              categories={categories}
              currentSlug={slug}
              onNavigate={() => setMobileMenu(false)}
            />
          </div>
        </div>
      )}

      {/* ── MAIN LAYOUT ── */}
      <div className="mx-auto flex max-w-[1440px] pt-14">
        {/* Desktop sidebar */}
        <aside className="hidden w-60 shrink-0 lg:block">
          <div className="fixed top-14 bottom-0 w-60 overflow-y-auto border-r border-[#1e2233]/40 p-5">
            <Sidebar categories={categories} currentSlug={slug} />

            <div className="mt-8 rounded-lg border border-[#1e2233]/40 bg-[#0a0c13] px-3 py-3">
              <p className="text-[11px] text-[#4a4e63] leading-relaxed">
                Install Janus
              </p>
              <code
                className="mt-1.5 block text-[11px] text-[#5eead4]"
                style={{ fontFamily: "var(--font-mono)" }}
              >
                pip install janus-security
              </code>
            </div>
          </div>
        </aside>

        {/* Content */}
        <main className="min-w-0 flex-1 px-6 py-10 lg:px-12 lg:py-12">
          {/* Breadcrumb */}
          <div className="mb-8 flex items-center gap-2 text-[12px] text-[#4a4e63]">
            <Link
              href="/docs/quickstart"
              className="transition-colors hover:text-[#636880]"
            >
              Docs
            </Link>
            <ChevronRight size={10} />
            <span className="text-[#8b8fa3]">{section.shortTitle}</span>
          </div>

          {/* Markdown content */}
          <article className="doc-content max-w-3xl">
            <ReactMarkdown
              remarkPlugins={[remarkGfm]}
              rehypePlugins={[rehypeSlug, rehypeRaw]}
              components={{
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
                code({ className, children, ref: _ref, ...props }) {
                  // code component only handles inline code.
                  // Block code is handled by the pre component below.
                  return (
                    <code className="doc-inline-code" {...props}>
                      {children}
                    </code>
                  );
                },
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
                pre({ children, ref: _ref, ...props }) {
                  // Extract className and children from the nested <code> element
                  let lang = "";
                  let codeChildren: ReactNode = children;

                  if (
                    children &&
                    typeof children === "object" &&
                    "props" in children
                  ) {
                    const codeProps = (children as { props: { className?: string; children?: ReactNode } }).props;
                    lang = codeProps.className?.replace("language-", "") || "";
                    codeChildren = codeProps.children;
                  }

                  return (
                    <CodeBlock className={lang ? `language-${lang}` : undefined}>
                      {codeChildren}
                    </CodeBlock>
                  );
                },
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
                table({ children, ref: _ref, ...props }) {
                  return (
                    <div className="doc-table-wrap">
                      <table {...props}>{children}</table>
                    </div>
                  );
                },
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
                a({ children, href, ref: _ref, ...props }) {
                  const isExternal = href?.startsWith("http");
                  return (
                    <a
                      href={href}
                      {...(isExternal
                        ? { target: "_blank", rel: "noopener noreferrer" }
                        : {})}
                      className="doc-link"
                      {...props}
                    >
                      {children}
                      {isExternal && (
                        <ExternalLink
                          size={10}
                          className="ml-0.5 inline-block"
                        />
                      )}
                    </a>
                  );
                },
              }}
            >
              {content}
            </ReactMarkdown>
          </article>

          {/* Bottom nav */}
          <div className="mt-16 max-w-3xl border-t border-[#1e2233]/40 pt-8">
            <NavigationFooter slug={slug} categories={categories} />
          </div>
        </main>

        {/* Table of contents — desktop */}
        <aside className="hidden w-52 shrink-0 xl:block">
          <div className="fixed top-14 bottom-0 w-52 overflow-y-auto p-5 pt-12">
            <div className="flex items-center justify-between mb-1">
              <button
                onClick={() => setTocCollapsed(!tocCollapsed)}
                className="flex items-center gap-1 text-[10px] font-bold uppercase tracking-[0.15em] text-[#4a4e63] hover:text-[#636880]"
              >
                <ChevronDown
                  size={10}
                  className={`transition-transform ${tocCollapsed ? "-rotate-90" : ""}`}
                />
              </button>
            </div>
            {!tocCollapsed && (
              <TableOfContents
                entries={tocEntries}
                activeId={activeHeading}
              />
            )}
          </div>
        </aside>
      </div>

      {/* Search overlay */}
      {searchOpen && (
        <SearchOverlay
          categories={categories}
          onClose={() => setSearchOpen(false)}
        />
      )}

      {/* ── STYLES ── */}
      <style>{`
        /* ── PROSE ── */
        .doc-content {
          line-height: 1.75;
          font-size: 14.5px;
          color: #b0b4c4;
        }

        .doc-content > *:first-child {
          margin-top: 0;
        }

        /* Headings */
        .doc-content h1 {
          font-family: var(--font-serif);
          font-size: 2rem;
          font-weight: 400;
          color: #e4e7ef;
          margin: 0 0 1.5rem;
          letter-spacing: -0.02em;
          line-height: 1.2;
        }

        .doc-content h2 {
          font-family: var(--font-sans);
          font-size: 1.35rem;
          font-weight: 600;
          color: #e4e7ef;
          margin: 3rem 0 1rem;
          padding-bottom: 0.6rem;
          border-bottom: 1px solid rgba(30, 34, 51, 0.5);
          letter-spacing: -0.01em;
          line-height: 1.3;
        }

        .doc-content h2:hover::after {
          content: " #";
          color: #5eead4;
          opacity: 0.4;
          font-size: 0.8em;
        }

        .doc-content h3 {
          font-family: var(--font-sans);
          font-size: 1.05rem;
          font-weight: 600;
          color: #d0d3e0;
          margin: 2rem 0 0.75rem;
          letter-spacing: -0.005em;
        }

        .doc-content h4 {
          font-family: var(--font-sans);
          font-size: 0.9rem;
          font-weight: 600;
          color: #b0b4c4;
          margin: 1.5rem 0 0.5rem;
        }

        /* Paragraphs */
        .doc-content p {
          margin: 0 0 1rem;
        }

        /* Lists */
        .doc-content ul {
          list-style: none;
          padding-left: 0;
          margin: 0 0 1rem;
        }

        .doc-content ul li {
          position: relative;
          padding-left: 1.25rem;
          margin-bottom: 0.35rem;
        }

        .doc-content ul li::before {
          content: "";
          position: absolute;
          left: 0.25rem;
          top: 0.65em;
          width: 4px;
          height: 4px;
          border-radius: 50%;
          background: #5eead4;
          opacity: 0.5;
        }

        .doc-content ol {
          padding-left: 1.5rem;
          margin: 0 0 1rem;
        }

        .doc-content ol li {
          margin-bottom: 0.35rem;
        }

        .doc-content ol li::marker {
          color: #5eead4;
          opacity: 0.6;
          font-size: 0.85em;
          font-weight: 600;
        }

        /* Links */
        .doc-link {
          color: #5eead4;
          text-decoration: none;
          transition: color 0.15s;
          border-bottom: 1px solid transparent;
        }

        .doc-link:hover {
          color: #2dd4bf;
          border-bottom-color: #2dd4bf40;
        }

        /* Inline code */
        .doc-inline-code {
          font-family: var(--font-mono);
          font-size: 0.82em;
          padding: 0.15em 0.4em;
          border-radius: 4px;
          background: rgba(94, 234, 212, 0.06);
          color: #5eead4;
          border: 1px solid rgba(94, 234, 212, 0.08);
        }

        /* Code blocks */
        .doc-code-block {
          position: relative;
          margin: 0 0 1.25rem;
          border-radius: 10px;
          border: 1px solid #1e2233;
          background: #080a11;
          overflow: hidden;
        }

        .doc-code-lang {
          position: absolute;
          top: 0;
          right: 0;
          padding: 4px 10px;
          font-family: var(--font-mono);
          font-size: 10px;
          color: #4a4e63;
          border-bottom-left-radius: 6px;
          border-left: 1px solid #1e2233;
          border-bottom: 1px solid #1e2233;
          background: #0a0c13;
          letter-spacing: 0.05em;
          text-transform: uppercase;
        }

        .doc-pre {
          margin: 0;
          padding: 1rem 1.25rem;
          overflow-x: auto;
          font-family: var(--font-mono);
          font-size: 12.5px;
          line-height: 1.7;
          color: #b0b4c4;
        }

        .doc-pre::-webkit-scrollbar {
          height: 6px;
        }

        .doc-pre::-webkit-scrollbar-track {
          background: transparent;
        }

        .doc-pre::-webkit-scrollbar-thumb {
          background: #1e2233;
          border-radius: 3px;
        }

        /* ASCII Diagrams — special styling */
        .doc-diagram {
          position: relative;
          margin: 0 0 1.5rem;
          border-radius: 12px;
          border: 1px solid rgba(94, 234, 212, 0.12);
          background: linear-gradient(135deg, #080a11 0%, #0a0e16 100%);
          overflow: hidden;
        }

        .doc-diagram::before {
          content: "DIAGRAM";
          position: absolute;
          top: 0;
          right: 0;
          padding: 3px 10px;
          font-family: var(--font-mono);
          font-size: 9px;
          letter-spacing: 0.12em;
          color: #5eead4;
          opacity: 0.35;
          border-bottom-left-radius: 6px;
          border-left: 1px solid rgba(94, 234, 212, 0.08);
          border-bottom: 1px solid rgba(94, 234, 212, 0.08);
          background: rgba(94, 234, 212, 0.04);
        }

        .doc-diagram-pre {
          margin: 0;
          padding: 1.5rem 1.5rem;
          overflow-x: auto;
          font-family: 'Courier New', 'Courier', monospace;
          font-size: 12px;
          line-height: 1.45;
          color: #8b9cc4;
          white-space: pre;
          -webkit-font-smoothing: auto;
          -moz-osx-font-smoothing: auto;
        }

        .doc-diagram-pre::-webkit-scrollbar {
          height: 6px;
        }

        .doc-diagram-pre::-webkit-scrollbar-track {
          background: transparent;
        }

        .doc-diagram-pre::-webkit-scrollbar-thumb {
          background: rgba(94, 234, 212, 0.15);
          border-radius: 3px;
        }

        /* Tables */
        .doc-table-wrap {
          margin: 0 0 1.25rem;
          overflow-x: auto;
          border-radius: 10px;
          border: 1px solid #1e2233;
        }

        .doc-table-wrap::-webkit-scrollbar {
          height: 6px;
        }

        .doc-table-wrap::-webkit-scrollbar-thumb {
          background: #1e2233;
          border-radius: 3px;
        }

        .doc-content table {
          width: 100%;
          border-collapse: collapse;
          font-size: 13px;
        }

        .doc-content thead {
          background: #0a0c13;
        }

        .doc-content th {
          padding: 0.65rem 1rem;
          text-align: left;
          font-weight: 600;
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 0.06em;
          color: #636880;
          border-bottom: 1px solid #1e2233;
          white-space: nowrap;
        }

        .doc-content td {
          padding: 0.6rem 1rem;
          border-bottom: 1px solid #1e2233/40;
          color: #9498ad;
          vertical-align: top;
        }

        .doc-content tr:last-child td {
          border-bottom: none;
        }

        .doc-content tbody tr:hover {
          background: rgba(255, 255, 255, 0.015);
        }

        /* Blockquotes */
        .doc-content blockquote {
          margin: 0 0 1rem;
          padding: 0.75rem 1rem;
          border-left: 3px solid #5eead4;
          background: rgba(94, 234, 212, 0.04);
          border-radius: 0 8px 8px 0;
          color: #8b8fa3;
          font-size: 13.5px;
        }

        .doc-content blockquote p:last-child {
          margin-bottom: 0;
        }

        /* Horizontal rules */
        .doc-content hr {
          margin: 2.5rem 0;
          border: none;
          border-top: 1px solid #1e2233;
        }

        /* Strong / emphasis */
        .doc-content strong {
          color: #d8dbe6;
          font-weight: 600;
        }

        .doc-content em {
          color: #9ea2b8;
          font-style: italic;
        }

        /* Images */
        .doc-content img {
          max-width: 100%;
          border-radius: 8px;
          border: 1px solid #1e2233;
        }

        /* Nested lists */
        .doc-content ul ul,
        .doc-content ol ul,
        .doc-content ul ol {
          margin-top: 0.35rem;
          margin-bottom: 0;
        }

        /* Selection */
        .doc-content ::selection {
          background: rgba(94, 234, 212, 0.2);
          color: #e4e7ef;
        }
      `}</style>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════
   PREV/NEXT NAVIGATION
   ═══════════════════════════════════════════════════════════════ */

function NavigationFooter({
  slug,
  categories,
}: {
  slug: string;
  categories: Category[];
}) {
  const allSections = categories.flatMap((c) => c.sections);
  const idx = allSections.findIndex((s) => s.slug === slug);
  const prev = idx > 0 ? allSections[idx - 1] : null;
  const next = idx < allSections.length - 1 ? allSections[idx + 1] : null;

  return (
    <div className="flex items-stretch gap-4">
      {prev ? (
        <Link
          href={`/docs/${prev.slug}`}
          className="group flex flex-1 flex-col items-start rounded-xl border border-[#1e2233]/60 bg-[#0a0c13] p-4 transition-all hover:border-[#5eead4]/20 hover:bg-[#0c0e16]"
        >
          <span className="mb-1 text-[11px] text-[#4a4e63]">Previous</span>
          <span className="flex items-center gap-1.5 text-[13px] font-medium text-[#8b8fa3] group-hover:text-[#5eead4]">
            <ArrowLeft size={12} />
            {prev.shortTitle}
          </span>
        </Link>
      ) : (
        <div className="flex-1" />
      )}
      {next ? (
        <Link
          href={`/docs/${next.slug}`}
          className="group flex flex-1 flex-col items-end rounded-xl border border-[#1e2233]/60 bg-[#0a0c13] p-4 transition-all hover:border-[#5eead4]/20 hover:bg-[#0c0e16]"
        >
          <span className="mb-1 text-[11px] text-[#4a4e63]">Next</span>
          <span className="flex items-center gap-1.5 text-[13px] font-medium text-[#8b8fa3] group-hover:text-[#5eead4]">
            {next.shortTitle}
            <ChevronRight size={12} />
          </span>
        </Link>
      ) : (
        <div className="flex-1" />
      )}
    </div>
  );
}
