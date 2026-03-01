"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import { ROLE_COLORS, TAINT_COLORS, riskColor, verdictBadge } from "@/lib/theme";
import { RiskTimeline } from "./RiskTimeline";
import { PipelineBreakdown } from "./PipelineBreakdown";
import ProofChainPanel from "@/components/ProofChainPanel";
import TaintFlowPanel from "@/components/TaintFlowPanel";
import { ApprovalQueue, type ApprovalRequest } from "./ApprovalQueue";
import type {
  Agent,
  RiskEvent,
  Session,
  TaintEntry,
  Trace,
  WsEvent,
} from "./MonitorPage";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface Props {
  sessionId: string;
  agents: Agent[];
  sessions: Session[];
  globalEvents: WsEvent[];
  approvals?: ApprovalRequest[];
  onApprovalResolved?: (id: string) => void;
  onBack: () => void;
}

export function SessionDetail({
  sessionId,
  agents,
  sessions,
  globalEvents,
  approvals = [],
  onApprovalResolved,
  onBack,
}: Props) {
  const [riskEvents, setRiskEvents] = useState<RiskEvent[]>([]);
  const [taints, setTaints] = useState<TaintEntry[]>([]);
  const [traces, setTraces] = useState<Trace[]>([]);
  const [expandedTrace, setExpandedTrace] = useState<string | null>(null);

  const session = sessions.find((s) => s.session_id === sessionId);
  const agent = useMemo(
    () => agents.find((a) => a.agent_id === session?.agent_id),
    [agents, session],
  );
  const role = agent?.role ?? "unknown";
  const rc = ROLE_COLORS[role] ?? ROLE_COLORS.research;

  // Live events for this session (newest first)
  const sessionEvents = useMemo(
    () => globalEvents.filter((e) => e.session_id === sessionId),
    [globalEvents, sessionId],
  );

  /* ── Fetch on mount ─────────────────────────────────────────── */

  const fetchData = useCallback(async () => {
    const [evRes, taintRes, traceRes] = await Promise.allSettled([
      apiFetch(`${API}/api/sessions/${sessionId}/events`),
      apiFetch(`${API}/api/sessions/${sessionId}/taint`),
      apiFetch(`${API}/api/traces?session_id=${sessionId}`),
    ]);
    if (evRes.status === "fulfilled" && evRes.value.ok)
      setRiskEvents(await evRes.value.json());
    if (taintRes.status === "fulfilled" && taintRes.value.ok)
      setTaints(await taintRes.value.json());
    if (traceRes.status === "fulfilled" && traceRes.value.ok)
      setTraces(await traceRes.value.json());
  }, [sessionId]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // Merge live WS risk events with initially fetched ones
  const allRiskEvents = useMemo(() => {
    const liveRisk: RiskEvent[] = sessionEvents.map((e) => ({
      risk_delta: e.data.risk_delta,
      new_score: e.data.risk_score,
      tool_name: e.data.tool_name,
      reason: e.data.recommended_action ?? "",
      timestamp: e.timestamp,
    }));
    // Deduplicate by timestamp
    const seen = new Set(riskEvents.map((r) => r.timestamp));
    const merged = [...riskEvents];
    for (const r of liveRisk) {
      if (!seen.has(r.timestamp)) {
        merged.push(r);
        seen.add(r.timestamp);
      }
    }
    return merged;
  }, [riskEvents, sessionEvents]);

  /* ── Build event feed: prefer WS events (have check_results), fall back to traces ── */

  interface FeedItem {
    id: string;
    tool_name: string;
    verdict: string;
    risk_score: number;
    risk_delta: number;
    reasons: string[];
    timestamp: string;
    check_results?: NonNullable<WsEvent["data"]["check_results"]>;
  }

  const feedItems: FeedItem[] = useMemo(() => {
    const items: FeedItem[] = [];
    const seenIds = new Set<string>();

    // WS events first (they have check_results)
    for (const e of sessionEvents) {
      const id = e.data.trace_id || e.timestamp;
      if (!seenIds.has(id)) {
        seenIds.add(id);
        items.push({
          id,
          tool_name: e.data.tool_name,
          verdict: e.data.verdict,
          risk_score: e.data.risk_score,
          risk_delta: e.data.risk_delta,
          reasons: e.data.reasons,
          timestamp: e.timestamp,
          check_results: e.data.check_results,
        });
      }
    }

    // Then traces (for events before WS connected)
    for (const t of traces) {
      if (!seenIds.has(t.trace_id)) {
        seenIds.add(t.trace_id);
        items.push({
          id: t.trace_id,
          tool_name: t.tool_name,
          verdict: t.verdict,
          risk_score: t.risk_score,
          risk_delta: t.risk_delta,
          reasons: t.reasons,
          timestamp: t.timestamp,
        });
      }
    }

    // Sort newest first
    items.sort((a, b) => b.timestamp.localeCompare(a.timestamp));
    return items;
  }, [sessionEvents, traces]);

  // Map events to the SecurityEvent shape TaintFlowPanel expects
  const taintFlowEvents = useMemo(() => {
    // Prefer live WS events (richer data), supplement with historical traces
    const events: { event_type: string; session_id: string; data: Record<string, unknown>; timestamp: string }[] = [];
    const seenIds = new Set<string>();

    for (const e of sessionEvents) {
      const id = e.data.trace_id || e.timestamp;
      if (!seenIds.has(id)) {
        seenIds.add(id);
        events.push({
          event_type: e.event_type,
          session_id: e.session_id,
          data: e.data as Record<string, unknown>,
          timestamp: e.timestamp,
        });
      }
    }

    // Add historical traces not covered by WS
    for (const t of traces) {
      if (!seenIds.has(t.trace_id)) {
        seenIds.add(t.trace_id);
        events.push({
          event_type: "verdict",
          session_id: t.session_id,
          data: {
            verdict: t.verdict,
            risk_score: t.risk_score,
            risk_delta: t.risk_delta,
            tool_name: t.tool_name,
            reasons: t.reasons,
          },
          timestamp: t.timestamp,
        });
      }
    }

    // Sort chronologically for flow visualization
    events.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
    return events;
  }, [sessionEvents, traces]);

  return (
    <div>
      {/* Back button + session header */}
      <button
        onClick={onBack}
        className="mb-4 flex items-center gap-1.5 text-sm text-[#8888a0] transition-colors hover:text-[#e0e0e8]"
      >
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M19 12H5" />
          <path d="M12 19l-7-7 7-7" />
        </svg>
        Back to overview
      </button>

      <div className="mb-5 flex flex-wrap items-center gap-3">
        <h2 className="text-base font-semibold text-[#e0e0e8]">
          {agent?.name ?? session?.agent_id ?? "Unknown"}
        </h2>
        <span
          className={`rounded-full px-2 py-0.5 text-[10px] font-mono uppercase ${rc.bg} ${rc.text} border ${rc.border}`}
        >
          {role}
        </span>
        <span className="font-mono text-xs text-[#555570]">{sessionId}</span>
        {session && (
          <span
            className={`ml-auto font-mono text-xl font-bold ${riskColor(session.risk_score)}`}
          >
            {session.risk_score.toFixed(1)}
          </span>
        )}
      </div>

      {/* 2-column layout */}
      <div className="grid gap-4 lg:grid-cols-[1fr_340px]">
        {/* Left: Risk timeline + approvals + event feed */}
        <div className="flex flex-col gap-4">
          <RiskTimeline events={allRiskEvents} />

          {/* Session-scoped approval queue */}
          {approvals.length > 0 && onApprovalResolved && (
            <ApprovalQueue
              approvals={approvals}
              onResolved={onApprovalResolved}
            />
          )}

          {/* Event feed */}
          <div className="rounded-xl border border-[#2a2a3e] bg-[#12121a]/80 p-4">
            <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-[#555570]">
              Event Feed ({feedItems.length})
            </h3>
            <div className="flex flex-col gap-2 max-h-[500px] overflow-y-auto pr-1">
              {feedItems.length === 0 ? (
                <p className="py-4 text-center text-sm text-[#555570]">
                  No events recorded
                </p>
              ) : (
                feedItems.map((item) => {
                  const vb = verdictBadge(item.verdict);
                  const isExpanded = expandedTrace === item.id;

                  return (
                    <div key={item.id} className="rounded-lg border border-[#2a2a3e] bg-[#0a0a0f]/60">
                      <button
                        onClick={() =>
                          setExpandedTrace(isExpanded ? null : item.id)
                        }
                        className="flex w-full items-center gap-2 px-3 py-2 text-left"
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
                        <span className="font-mono text-xs text-[#e0e0e8]">
                          {item.tool_name}
                        </span>
                        <span
                          className={`rounded-full px-1.5 py-0.5 text-[9px] font-mono uppercase ${vb.bg} ${vb.text}`}
                        >
                          {vb.label}
                        </span>
                        {item.risk_delta > 0 && (
                          <span className="font-mono text-[10px] text-red-400/70">
                            +{item.risk_delta.toFixed(1)}
                          </span>
                        )}
                        <span className="ml-auto font-mono text-[10px] text-[#555570]">
                          {item.risk_score.toFixed(1)}
                        </span>
                      </button>
                      {isExpanded && (
                        <div className="border-t border-[#2a2a3e] px-3 py-2">
                          <PipelineBreakdown
                            checkResults={item.check_results}
                            reasons={item.reasons}
                          />
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          </div>
        </div>

        {/* Right: Taint flow + Proof chain + session info */}
        <div className="flex flex-col gap-4">
          {/* Taint Flow Visualization */}
          <div className="rounded-xl border border-[#2a2a3e] bg-[#12121a]/80 overflow-hidden max-h-[400px]">
            <TaintFlowPanel
              events={taintFlowEvents}
              sessionId={sessionId}
            />
          </div>

          {/* Proof Chain */}
          <div className="rounded-xl border border-[#2a2a3e] bg-[#12121a]/80 overflow-hidden max-h-[400px]">
            <ProofChainPanel
              sessionId={sessionId}
              eventCount={feedItems.length}
            />
          </div>

          {/* Session goal */}
          {session?.original_goal && (
            <div className="rounded-xl border border-[#2a2a3e] bg-[#12121a]/80 p-4">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest text-[#555570]">
                Original Goal
              </h3>
              <p className="text-sm leading-relaxed text-[#8888a0]">
                {session.original_goal}
              </p>
            </div>
          )}

          {/* Agent permissions */}
          {agent && (
            <div className="rounded-xl border border-[#2a2a3e] bg-[#12121a]/80 p-4">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-widest text-[#555570]">
                Permissions
              </h3>
              <div className="flex flex-wrap gap-1">
                {agent.permissions.map((p) => (
                  <span
                    key={p}
                    className="rounded bg-[#1a1a2e] px-1.5 py-0.5 font-mono text-[10px] text-[#8888a0]"
                  >
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
