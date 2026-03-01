"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";
import { StatsBar } from "./StatsBar";
import { SessionGrid } from "./SessionGrid";
import { SessionDetail } from "./SessionDetail";
import { ApprovalQueue, type ApprovalRequest } from "./ApprovalQueue";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/* ── Shared types ───────────────────────────────────────────────── */

export interface Session {
  session_id: string;
  agent_id: string;
  original_goal: string;
  risk_score: number;
}

export interface Agent {
  agent_id: string;
  name: string;
  role: string;
  permissions: string[];
  is_locked: boolean;
}

export interface HealthFull {
  status: string;
  total_requests: number;
  successful_requests: number;
  failed_requests: number;
  avg_latency_ms: number;
  p95_latency_ms: number;
  error_rate: number;
  circuit_breaker: string;
  active_sessions: number;
}

export interface CheckResultData {
  check_name: string;
  passed: boolean;
  risk_contribution: number;
  reason: string;
  metadata: Record<string, unknown>;
  force_verdict: string | null;
}

export interface WsEvent {
  event_type: string;
  session_id: string;
  data: {
    verdict: string;
    risk_score: number;
    risk_delta: number;
    tool_name: string;
    tool_input: Record<string, unknown>;
    reasons: string[];
    drift_score?: number;
    itdr_signals?: string[];
    recommended_action?: string;
    trace_id?: string;
    check_results?: CheckResultData[];
    // Approval fields (present on approval_created/approval_resolved events)
    id?: string;
    status?: string;
    resolution?: string;
  };
  timestamp: string;
}

export interface RiskEvent {
  risk_delta: number;
  new_score: number;
  tool_name: string;
  reason: string;
  timestamp: string;
}

export interface TaintEntry {
  label: string;
  source_tool: string;
  source_step: number;
  patterns_matched: string[];
  timestamp: string;
}

export interface Trace {
  trace_id: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  verdict: string;
  risk_score: number;
  risk_delta: number;
  explanation: string;
  timestamp: string;
  reasons: string[];
}

/* ── Component ──────────────────────────────────────────────────── */

const MAX_EVENTS = 200;

export function MonitorPage() {
  const [sessions, setSessions] = useState<Session[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const [globalEvents, setGlobalEvents] = useState<WsEvent[]>([]);
  const [health, setHealth] = useState<HealthFull | null>(null);
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  /* ── Fetch helpers ──────────────────────────────────────────── */

  const fetchSessions = useCallback(async () => {
    try {
      const res = await apiFetch(`${API}/api/sessions`);
      if (res.ok) setSessions(await res.json());
    } catch { /* silent */ }
  }, []);

  const fetchAgents = useCallback(async () => {
    try {
      const res = await apiFetch(`${API}/api/agents`);
      if (res.ok) setAgents(await res.json());
    } catch { /* silent */ }
  }, []);

  const fetchHealth = useCallback(async () => {
    try {
      const res = await apiFetch(`${API}/api/health/full`);
      if (res.ok) setHealth(await res.json());
    } catch { /* silent */ }
  }, []);

  const fetchApprovals = useCallback(async () => {
    try {
      const res = await apiFetch(`${API}/api/approvals?status=pending`);
      if (res.ok) {
        const fresh: ApprovalRequest[] = await res.json();
        // Use canonical API data but don't flash — deduplicate by id
        setApprovals(fresh);
      }
    } catch { /* silent */ }
  }, []);

  /* ── WebSocket ──────────────────────────────────────────────── */

  const connectWs = useCallback(() => {
    const wsBase = API.replace(/^http/, "ws");
    const ws = new WebSocket(`${wsBase}/api/ws/monitor`);

    ws.onmessage = (msg) => {
      try {
        const event: WsEvent = JSON.parse(msg.data);

        // Handle approval events
        if (event.event_type === "approval_created") {
          setApprovals((prev) => {
            // Avoid duplicates
            if (prev.some((a) => a.id === event.data.id)) return prev;
            return [event.data as unknown as ApprovalRequest, ...prev];
          });
          return;
        }
        if (event.event_type === "approval_resolved") {
          setApprovals((prev) => prev.filter((a) => a.id !== event.data.id));
          return;
        }

        // Regular verdict events
        setGlobalEvents((prev) => {
          const next = [event, ...prev];
          return next.length > MAX_EVENTS ? next.slice(0, MAX_EVENTS) : next;
        });
        // Update session risk score from live events
        if (event.data?.risk_score != null) {
          setSessions((prev) =>
            prev.map((s) =>
              s.session_id === event.session_id
                ? { ...s, risk_score: event.data.risk_score }
                : s,
            ),
          );
        }
      } catch { /* malformed message */ }
    };

    ws.onclose = () => {
      reconnectTimer.current = setTimeout(connectWs, 3000);
    };

    ws.onerror = () => ws.close();

    wsRef.current = ws;
  }, []);

  /* ── Lifecycle ──────────────────────────────────────────────── */

  useEffect(() => {
    fetchSessions();
    fetchAgents();
    fetchHealth();
    fetchApprovals();
    connectWs();

    const poll = setInterval(() => {
      fetchSessions();
      fetchHealth();
      fetchApprovals();
    }, 5000);

    return () => {
      clearInterval(poll);
      clearTimeout(reconnectTimer.current);
      wsRef.current?.close();
    };
  }, [fetchSessions, fetchAgents, fetchHealth, fetchApprovals, connectWs]);

  const handleApprovalResolved = useCallback((id: string) => {
    setApprovals((prev) => prev.filter((a) => a.id !== id));
  }, []);

  /* ── Render ─────────────────────────────────────────────────── */

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-[#e0e0e8]">
      {/* Subtle grid overlay */}
      <div
        className="pointer-events-none fixed inset-0 opacity-[0.03]"
        style={{
          backgroundImage:
            "linear-gradient(#8888a0 1px, transparent 1px), linear-gradient(90deg, #8888a0 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
      />

      <div className="relative z-10 mx-auto max-w-[1600px] p-4 md:p-6">
        {/* Header */}
        <div className="mb-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-[#00ff88]/10 border border-[#00ff88]/20">
              <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#00ff88" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight">Janus Monitor</h1>
              <p className="text-xs text-[#555570]">Production Security Dashboard</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[#00ff88] opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-[#00ff88]" />
            </span>
            <span className="text-xs font-mono text-[#00ff88]/70">LIVE</span>
          </div>
        </div>

        {/* Stats bar */}
        <StatsBar
          health={health}
          sessions={sessions}
          eventCount={globalEvents.length}
          blockedCount={globalEvents.filter((e) => e.data?.verdict === "block").length}
          pendingApprovals={approvals.length}
        />

        {/* Main content */}
        {selectedSessionId ? (
          <SessionDetail
            sessionId={selectedSessionId}
            agents={agents}
            sessions={sessions}
            globalEvents={globalEvents}
            approvals={approvals.filter((a) => a.session_id === selectedSessionId)}
            onApprovalResolved={handleApprovalResolved}
            onBack={() => setSelectedSessionId(null)}
          />
        ) : (
          <>
            {/* Approval queue — above session grid */}
            <ApprovalQueue
              approvals={approvals}
              onResolved={handleApprovalResolved}
            />
            <SessionGrid
              sessions={sessions}
              agents={agents}
              globalEvents={globalEvents}
              approvals={approvals}
              onSelect={setSelectedSessionId}
            />
          </>
        )}
      </div>
    </div>
  );
}
