"use client";

import { useState } from "react";
import { apiFetch } from "@/lib/api";
import { verdictBadge, riskColor } from "@/lib/theme";
import { PipelineBreakdown } from "./PipelineBreakdown";
import type { CheckResultData } from "./MonitorPage";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export interface ApprovalRequest {
  id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  tool_input: Record<string, unknown>;
  original_goal: string;
  verdict: string;
  risk_score: number;
  risk_delta: number;
  reasons: string[];
  check_results: CheckResultData[];
  trace_id: string;
  status: string;
  decided_by: string | null;
  decided_at: string | null;
  decision_reason: string;
  tool_result: Record<string, unknown> | null;
  created_at: string;
  expires_at: string | null;
}

interface Props {
  approvals: ApprovalRequest[];
  onResolved: (id: string) => void;
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

export function ApprovalQueue({ approvals, onResolved }: Props) {
  const [expanded, setExpanded] = useState<string | null>(null);
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});
  const [results, setResults] = useState<Record<string, { action: string; tool_result?: Record<string, unknown> | null }>>({});

  if (approvals.length === 0 && Object.keys(results).length === 0) return null;

  const handleDecision = async (id: string, action: "approve" | "reject") => {
    setLoading((prev) => ({ ...prev, [id]: true }));
    try {
      const res = await apiFetch(`${API}/api/approvals/${id}/${action}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          decided_by: "human",
          reason: reasons[id] || "",
        }),
      });
      if (res.ok) {
        const data = await res.json();
        // Show result briefly before removing
        setResults((prev) => ({
          ...prev,
          [id]: { action, tool_result: data.tool_result },
        }));
        // Remove from queue after showing result
        setTimeout(() => {
          onResolved(id);
          setResults((prev) => {
            const next = { ...prev };
            delete next[id];
            return next;
          });
        }, 3000);
      }
    } catch {
      /* silent */
    } finally {
      setLoading((prev) => ({ ...prev, [id]: false }));
    }
  };

  return (
    <div className="mb-6 rounded-xl border-2 border-orange-500/40 bg-[#12121a]/80 backdrop-blur-sm">
      {/* Header */}
      <div className="flex items-center gap-3 border-b border-orange-500/20 px-4 py-3">
        <div className="flex h-6 w-6 items-center justify-center rounded-md bg-orange-500/20">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#f97316" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        </div>
        <h3 className="text-sm font-semibold text-orange-400">
          Pending Approvals ({approvals.length})
        </h3>
        <span className="ml-auto text-[10px] text-[#555570]">
          Human review required
        </span>
      </div>

      {/* Items */}
      <div className="flex flex-col divide-y divide-[#2a2a3e]">
        {approvals.map((req) => {
          const vb = verdictBadge(req.verdict);
          const isExpanded = expanded === req.id;
          const isLoading = loading[req.id] ?? false;
          const result = results[req.id];

          return (
            <div key={req.id} className={`px-4 py-3 transition-opacity ${result ? "opacity-60" : ""}`}>
              {/* Result banner */}
              {result && (
                <div className={`mb-2 rounded-lg border px-3 py-2 text-xs font-medium ${
                  result.action === "approve"
                    ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-400"
                    : "border-red-500/30 bg-red-500/10 text-red-400"
                }`}>
                  {result.action === "approve" ? (
                    <>
                      Tool executed successfully
                      {result.tool_result && (
                        <pre className="mt-1 max-h-24 overflow-auto text-[10px] font-mono text-emerald-300/70 whitespace-pre-wrap">
                          {JSON.stringify(result.tool_result, null, 2)}
                        </pre>
                      )}
                    </>
                  ) : (
                    "Rejected — tool will not execute"
                  )}
                </div>
              )}

              {/* Summary row */}
              <button
                onClick={() => setExpanded(isExpanded ? null : req.id)}
                className="flex w-full items-center gap-3 text-left"
              >
                <svg
                  width="10"
                  height="10"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#555570"
                  strokeWidth="2"
                  className={`shrink-0 transition-transform ${isExpanded ? "rotate-90" : ""}`}
                >
                  <path d="M9 18l6-6-6-6" />
                </svg>

                <span className="font-mono text-xs text-[#8888a0]">
                  {req.agent_id}
                </span>
                <span className="font-mono text-xs font-medium text-[#e0e0e8]">
                  {req.tool_name}
                </span>
                <span className={`rounded-full px-1.5 py-0.5 text-[9px] font-mono uppercase ${vb.bg} ${vb.text}`}>
                  {vb.label}
                </span>
                <span className={`font-mono text-xs ${riskColor(req.risk_score)}`}>
                  {req.risk_score.toFixed(1)}
                </span>
                <span className="ml-auto text-[10px] text-[#555570]">
                  {timeAgo(req.created_at)}
                </span>
              </button>

              {/* Expanded detail */}
              {isExpanded && (
                <div className="mt-3 ml-5 flex flex-col gap-3">
                  {/* Pipeline breakdown */}
                  {req.check_results.length > 0 && (
                    <div className="rounded-lg border border-[#2a2a3e] bg-[#0a0a0f]/60 p-3">
                      <PipelineBreakdown
                        checkResults={req.check_results}
                        reasons={req.reasons}
                      />
                    </div>
                  )}

                  {/* Tool input */}
                  <div className="rounded-lg border border-[#2a2a3e] bg-[#0a0a0f]/60 p-3">
                    <h4 className="mb-1.5 text-[10px] font-semibold uppercase tracking-widest text-[#555570]">
                      Tool Input
                    </h4>
                    <pre className="max-h-32 overflow-auto text-[11px] font-mono text-[#8888a0] whitespace-pre-wrap">
                      {JSON.stringify(req.tool_input, null, 2)}
                    </pre>
                  </div>

                  {/* Reason input + actions (hidden once resolved) */}
                  {!result && (
                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        placeholder="Reason (optional)"
                        value={reasons[req.id] || ""}
                        onChange={(e) =>
                          setReasons((prev) => ({ ...prev, [req.id]: e.target.value }))
                        }
                        className="flex-1 rounded-lg border border-[#2a2a3e] bg-[#0a0a0f]/60 px-3 py-1.5 text-xs text-[#e0e0e8] placeholder-[#555570] outline-none focus:border-[#3a3a5e]"
                      />
                      <button
                        onClick={() => handleDecision(req.id, "approve")}
                        disabled={isLoading}
                        className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-400 transition-colors hover:bg-emerald-500/20 disabled:opacity-50"
                      >
                        {isLoading ? "..." : "Approve"}
                      </button>
                      <button
                        onClick={() => handleDecision(req.id, "reject")}
                        disabled={isLoading}
                        className="rounded-lg border border-red-500/30 bg-red-500/10 px-3 py-1.5 text-xs font-medium text-red-400 transition-colors hover:bg-red-500/20 disabled:opacity-50"
                      >
                        {isLoading ? "..." : "Reject"}
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
