"use client";

import { useMemo } from "react";
import { ROLE_COLORS, riskColor, riskBgColor } from "@/lib/theme";
import type { Agent, Session, WsEvent } from "./MonitorPage";
import type { ApprovalRequest } from "./ApprovalQueue";

interface Props {
  sessions: Session[];
  agents: Agent[];
  globalEvents: WsEvent[];
  approvals?: ApprovalRequest[];
  onSelect: (sessionId: string) => void;
}

export function SessionGrid({ sessions, agents, globalEvents, approvals = [], onSelect }: Props) {
  const agentMap = useMemo(
    () => Object.fromEntries(agents.map((a) => [a.agent_id, a])),
    [agents],
  );

  const eventsBySession = useMemo(() => {
    const map: Record<string, WsEvent[]> = {};
    for (const e of globalEvents) {
      (map[e.session_id] ??= []).push(e);
    }
    return map;
  }, [globalEvents]);

  const approvalsBySession = useMemo(() => {
    const map: Record<string, number> = {};
    for (const a of approvals) {
      map[a.session_id] = (map[a.session_id] ?? 0) + 1;
    }
    return map;
  }, [approvals]);

  const sorted = useMemo(
    () => [...sessions].sort((a, b) => b.risk_score - a.risk_score),
    [sessions],
  );

  if (sorted.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-[#555570]">
        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" className="mb-4 opacity-40">
          <rect x="3" y="3" width="18" height="18" rx="2" />
          <path d="M3 9h18" />
          <path d="M9 21V9" />
        </svg>
        <p className="text-sm">No active sessions</p>
        <p className="text-xs mt-1">Sessions will appear here when agents begin making tool calls</p>
      </div>
    );
  }

  return (
    <div className="grid gap-3 grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
      {sorted.map((session) => {
        const agent = agentMap[session.agent_id];
        const events = eventsBySession[session.session_id] ?? [];
        const pendingCount = approvalsBySession[session.session_id] ?? 0;
        const role = agent?.role ?? "unknown";
        const rc = ROLE_COLORS[role] ?? ROLE_COLORS.research;

        // Verdict distribution
        const allows = events.filter((e) => e.data?.verdict === "allow").length;
        const blocks = events.filter((e) => e.data?.verdict === "block").length;
        const others = events.length - allows - blocks;
        const total = events.length || 1;

        return (
          <button
            key={session.session_id}
            onClick={() => onSelect(session.session_id)}
            className="group relative flex flex-col gap-3 rounded-xl border border-[#2a2a3e] bg-[#12121a]/80 p-4 text-left transition-all hover:border-[#3a3a5e] hover:bg-[#1a1a2e]/80 hover:scale-[1.01] active:scale-[0.99]"
          >
            {/* Pending approval badge */}
            {pendingCount > 0 && (
              <div className="absolute -top-2 -right-2 flex h-5 min-w-5 items-center justify-center rounded-full bg-orange-500 px-1.5 text-[10px] font-bold text-white shadow-lg shadow-orange-500/30">
                {pendingCount}
              </div>
            )}

            {/* Agent + role */}
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2 min-w-0">
                <span className="truncate text-sm font-medium text-[#e0e0e8]">
                  {agent?.name ?? (session.agent_id || "Unknown Agent")}
                </span>
                <span
                  className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-mono uppercase ${rc.bg} ${rc.text} border ${rc.border}`}
                >
                  {role}
                </span>
              </div>
              {agent?.is_locked && (
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ff4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="shrink-0">
                  <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>
              )}
            </div>

            {/* Session ID */}
            <span className="font-mono text-[10px] text-[#555570] truncate">
              {session.session_id}
            </span>

            {/* Risk score + event count */}
            <div className="flex items-end justify-between">
              <div className="flex flex-col">
                <span className="text-[10px] uppercase tracking-widest text-[#555570]">Risk</span>
                <span
                  className={`font-mono text-2xl font-bold leading-none ${riskColor(session.risk_score)}`}
                >
                  {session.risk_score.toFixed(1)}
                </span>
              </div>
              <div className="flex flex-col items-end">
                <span className="text-[10px] uppercase tracking-widest text-[#555570]">Events</span>
                <span className="font-mono text-sm text-[#8888a0]">
                  {events.length}
                </span>
              </div>
            </div>

            {/* Mini verdict distribution bar */}
            {events.length > 0 && (
              <div className="flex h-1.5 w-full overflow-hidden rounded-full bg-[#1a1a2e]">
                {allows > 0 && (
                  <div
                    className="bg-emerald-500/60 transition-all"
                    style={{ width: `${(allows / total) * 100}%` }}
                  />
                )}
                {blocks > 0 && (
                  <div
                    className="bg-red-500/60 transition-all"
                    style={{ width: `${(blocks / total) * 100}%` }}
                  />
                )}
                {others > 0 && (
                  <div
                    className="bg-amber-500/40 transition-all"
                    style={{ width: `${(others / total) * 100}%` }}
                  />
                )}
              </div>
            )}

            {/* Risk background glow */}
            <div
              className={`pointer-events-none absolute inset-0 rounded-xl opacity-0 transition-opacity group-hover:opacity-100 ${riskBgColor(session.risk_score)}`}
              style={{ filter: "blur(40px)" }}
            />
          </button>
        );
      })}
    </div>
  );
}
