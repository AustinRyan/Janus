"use client";

import { useState } from "react";
import type { CheckResultData } from "./MonitorPage";

interface Props {
  checkResults?: CheckResultData[];
  reasons?: string[];
}

function MetadataExpander({ metadata }: { metadata: Record<string, unknown> }) {
  const [open, setOpen] = useState(false);
  const entries = Object.entries(metadata).filter(
    ([, v]) => v != null && v !== "" && !(Array.isArray(v) && v.length === 0),
  );
  if (entries.length === 0) return null;

  return (
    <div className="mt-1">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1 text-[10px] text-[#555570] hover:text-[#8888a0] transition-colors"
      >
        <svg
          width="10"
          height="10"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
          className={`transition-transform ${open ? "rotate-90" : ""}`}
        >
          <path d="M9 18l6-6-6-6" />
        </svg>
        metadata
      </button>
      {open && (
        <div className="mt-1 rounded-md bg-[#0a0a0f] p-2 font-mono text-[10px] text-[#8888a0] leading-relaxed">
          {entries.map(([k, v]) => (
            <div key={k}>
              <span className="text-[#555570]">{k}: </span>
              <span>{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export function PipelineBreakdown({ checkResults, reasons }: Props) {
  // If we have structured check_results, render the rich view
  if (checkResults && checkResults.length > 0) {
    return (
      <div className="flex flex-col gap-1.5">
        {checkResults.map((cr, i) => (
          <div
            key={`${cr.check_name}-${i}`}
            className="rounded-lg border border-[#2a2a3e] bg-[#0a0a0f]/60 px-3 py-2"
          >
            <div className="flex items-center gap-2">
              {/* Pass/fail icon */}
              {cr.passed ? (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#00ff88" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="shrink-0">
                  <polyline points="20 6 9 17 4 12" />
                </svg>
              ) : (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ff4444" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="shrink-0">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              )}

              {/* Check name */}
              <span className="font-mono text-xs text-[#e0e0e8]">
                {cr.check_name}
              </span>

              {/* Risk contribution */}
              {cr.risk_contribution > 0 && (
                <span className="ml-auto font-mono text-[10px] text-red-400/80">
                  +{cr.risk_contribution.toFixed(1)}
                </span>
              )}

              {/* Force verdict badge */}
              {cr.force_verdict && (
                <span
                  className={`rounded-full px-1.5 py-0.5 font-mono text-[9px] uppercase ${
                    cr.force_verdict === "block"
                      ? "bg-red-500/15 text-red-400"
                      : cr.force_verdict === "challenge"
                        ? "bg-amber-500/15 text-amber-400"
                        : "bg-blue-500/15 text-blue-400"
                  }`}
                >
                  {cr.force_verdict}
                </span>
              )}
            </div>

            {/* Reason */}
            {cr.reason && (
              <p className="mt-1 text-[11px] leading-relaxed text-[#8888a0]">
                {cr.reason}
              </p>
            )}

            {/* Expandable metadata */}
            <MetadataExpander metadata={cr.metadata} />
          </div>
        ))}
      </div>
    );
  }

  // Fallback: render from reasons[] for historic traces without check_results
  if (reasons && reasons.length > 0) {
    return (
      <div className="flex flex-col gap-1">
        {reasons.map((reason, i) => (
          <div
            key={i}
            className="flex items-start gap-2 rounded-lg border border-[#2a2a3e] bg-[#0a0a0f]/60 px-3 py-2"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#8888a0" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="mt-0.5 shrink-0">
              <circle cx="12" cy="12" r="10" />
              <line x1="12" y1="16" x2="12" y2="12" />
              <line x1="12" y1="8" x2="12.01" y2="8" />
            </svg>
            <span className="text-[11px] leading-relaxed text-[#8888a0]">
              {reason}
            </span>
          </div>
        ))}
      </div>
    );
  }

  return (
    <p className="text-xs text-[#555570] italic">No pipeline data available</p>
  );
}
