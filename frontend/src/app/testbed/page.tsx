"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { apiFetch } from "@/lib/api";
import { Shield, ArrowLeft, Cpu, Network, Lock, Zap, ShieldCheck, ShieldAlert } from "lucide-react";
import ChatPanel from "@/components/ChatPanel";
import ProofChainPanel from "@/components/ProofChainPanel";
import SecurityDashboard from "@/components/SecurityDashboard";
import ThreatIntelPanel from "@/components/ThreatIntelPanel";

const TESTBED_API = "http://localhost:8001";

interface Message {
  role: "user" | "assistant";
  content: string;
  toolCalls?: { tool_name: string; verdict: string; risk_score: number; risk_delta: number }[];
}

interface SecurityEvent {
  event_type: string;
  session_id: string;
  data: Record<string, unknown>;
  timestamp: string;
}

interface TestbedAgent {
  agent_id: string;
  name: string;
  role: string;
  permissions: string[];
  is_locked: boolean;
  tier: "free" | "pro";
  integration: "sdk" | "mcp";
  pipeline_checks: string[];
  pipeline_check_count: number;
  pro_only_checks: string[];
}

interface Session {
  sessionId: string;
  agentId: string;
  agentName: string;
  agentRole: string;
  agentPermissions: string[];
  tier: "free" | "pro";
  integration: "sdk" | "mcp";
  pipelineChecks: string[];
  proOnlyChecks: string[];
  messages: Message[];
  events: SecurityEvent[];
  riskScore: number;
  ws: WebSocket | null;
}

const ROLE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  research: { bg: "bg-blue-500/15", text: "text-blue-400", border: "border-blue-500/30" },
  code: { bg: "bg-green-500/15", text: "text-green-400", border: "border-green-500/30" },
  financial: { bg: "bg-amber-500/15", text: "text-amber-400", border: "border-amber-500/30" },
  admin: { bg: "bg-red-500/15", text: "text-red-400", border: "border-red-500/30" },
};

const CHECK_LABELS: Record<string, string> = {
  prompt_injection: "Prompt Injection",
  identity_check: "Identity",
  permission_scope: "Permissions",
  deterministic_risk: "Rule-Based Risk",
  llm_risk_classifier: "LLM Classifier",
  taint_analysis: "Taint Tracking",
  predictive_risk: "Predictive Risk",
  semantic_drift: "Drift Detection",
  threat_intel: "Threat Intel",
  itdr: "ITDR",
};

export default function TestbedPage() {
  const [agents, setAgents] = useState<TestbedAgent[]>([]);
  const [sessions, setSessions] = useState<Record<string, Session>>({});
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [activePanel, setActivePanel] = useState<"pipeline" | "proof" | "threat">("pipeline");

  // Fetch agents
  useEffect(() => {
    const fetchAgents = async () => {
      try {
        const resp = await apiFetch(`${TESTBED_API}/api/agents`);
        const data: TestbedAgent[] = await resp.json();
        setAgents(data);
      } catch (err) {
        console.error("Failed to fetch testbed agents:", err);
      }
    };
    fetchAgents();
  }, []);

  const connectWebSocket = useCallback((sessionId: string) => {
    const wsUrl = TESTBED_API.replace("http", "ws");
    const ws = new WebSocket(`${wsUrl}/api/ws/session/${sessionId}`);

    ws.onmessage = (event) => {
      const secEvent: SecurityEvent = JSON.parse(event.data);
      setSessions((prev) => {
        const session = prev[sessionId];
        if (!session) return prev;
        return {
          ...prev,
          [sessionId]: {
            ...session,
            events: [...session.events, secEvent],
            riskScore:
              secEvent.data.risk_score !== undefined
                ? (secEvent.data.risk_score as number)
                : session.riskScore,
          },
        };
      });
    };

    ws.onerror = (err) => console.error("WebSocket error:", err);
    return ws;
  }, []);

  const handleSelectAgent = useCallback(
    async (agent: TestbedAgent) => {
      try {
        const resp = await apiFetch(`${TESTBED_API}/api/sessions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ agent_id: agent.agent_id, original_goal: "" }),
        });
        const data = await resp.json();
        const sessionId: string = data.session_id;

        const ws = connectWebSocket(sessionId);

        const newSession: Session = {
          sessionId,
          agentId: agent.agent_id,
          agentName: agent.name,
          agentRole: agent.role,
          agentPermissions: agent.permissions,
          tier: agent.tier,
          integration: agent.integration,
          pipelineChecks: agent.pipeline_checks,
          proOnlyChecks: agent.pro_only_checks,
          messages: [],
          events: [],
          riskScore: 0,
          ws,
        };

        setSessions((prev) => ({ ...prev, [sessionId]: newSession }));
        setActiveSessionId(sessionId);
      } catch (err) {
        console.error("Failed to create session:", err);
      }
    },
    [connectWebSocket]
  );

  const handleSendMessage = useCallback(
    async (message: string) => {
      if (!activeSessionId) return;

      setSessions((prev) => {
        const session = prev[activeSessionId];
        if (!session) return prev;
        return {
          ...prev,
          [activeSessionId]: {
            ...session,
            messages: [...session.messages, { role: "user", content: message }],
          },
        };
      });
      setIsLoading(true);

      try {
        const resp = await apiFetch(`${TESTBED_API}/api/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ session_id: activeSessionId, message }),
        });
        const data = await resp.json();

        setSessions((prev) => {
          const session = prev[activeSessionId];
          if (!session) return prev;
          return {
            ...prev,
            [activeSessionId]: {
              ...session,
              messages: [
                ...session.messages,
                { role: "assistant", content: data.message, toolCalls: data.tool_calls },
              ],
            },
          };
        });
      } catch {
        setSessions((prev) => {
          const session = prev[activeSessionId];
          if (!session) return prev;
          return {
            ...prev,
            [activeSessionId]: {
              ...session,
              messages: [
                ...session.messages,
                { role: "assistant", content: "Error: Failed to get response from testbed backend." },
              ],
            },
          };
        });
      } finally {
        setIsLoading(false);
      }
    },
    [activeSessionId]
  );

  const activeSession = activeSessionId ? sessions[activeSessionId] : null;
  const activeAgent = activeSession ? agents.find(a => a.agent_id === activeSession.agentId) : null;

  return (
    <main className="h-screen flex flex-col bg-[#0a0a0f]">
      {/* Top bar */}
      <header className="flex items-center justify-between px-6 py-3 border-b border-[#2a2a3e] bg-[#0a0a0f]">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
          <h1 className="text-lg font-bold text-[#e0e0e8]">Janus Testbed</h1>
          <span className="text-xs text-[#555570]">4-Agent Manual Testing</span>
        </div>
        <div className="flex items-center gap-4">
          {activeSession && (
            <div className="flex items-center gap-3 text-xs text-[#8888a0]">
              <span className={`font-bold uppercase px-2 py-0.5 rounded text-[10px] ${
                activeSession.tier === "pro" ? "bg-violet-500/15 text-violet-400" : "bg-teal-500/15 text-teal-400"
              }`}>
                {activeSession.tier} tier
              </span>
              <span className="font-mono px-2 py-0.5 rounded text-[10px] bg-[#1a1a2e] text-[#555570]">
                {activeSession.pipelineChecks.length} checks
              </span>
              <span>
                Risk:{" "}
                <span
                  style={{
                    color:
                      activeSession.riskScore >= 80
                        ? "#ff4444"
                        : activeSession.riskScore >= 40
                        ? "#ffaa00"
                        : "#00ff88",
                  }}
                >
                  {activeSession.riskScore.toFixed(1)}
                </span>
              </span>
              <span>Events: {activeSession.events.length}</span>
            </div>
          )}
          <a
            href="/"
            className="flex items-center gap-1.5 text-xs text-[#555570] hover:text-[#8888a0] transition-colors"
          >
            <ArrowLeft size={12} />
            Main Dashboard
          </a>
        </div>
      </header>

      {/* Main layout */}
      <div className="flex-1 flex min-h-0">
        {/* Left sidebar — Agent selector */}
        <div className="w-64 min-w-[16rem] border-r border-[#2a2a3e] bg-[#0a0a0f] flex flex-col">
          <div className="px-4 py-3 border-b border-[#2a2a3e]">
            <div className="flex items-center gap-2">
              <Shield size={14} className="text-[#00ff88]" />
              <span className="text-xs font-semibold text-[#8888a0] uppercase tracking-wider">
                Agents
              </span>
            </div>
          </div>
          <div className="flex-1 overflow-y-auto p-3 space-y-2">
            {agents.map((agent) => {
              const style = ROLE_COLORS[agent.role] || { bg: "bg-gray-500/15", text: "text-gray-400", border: "border-gray-500/30" };
              const isActive = activeSession?.agentId === agent.agent_id;
              return (
                <button
                  key={agent.agent_id}
                  onClick={() => handleSelectAgent(agent)}
                  className={`w-full text-left rounded-lg border p-3 transition-all hover:scale-[1.01] ${
                    isActive
                      ? `${style.border} bg-[#1a1a2e] ring-1 ring-[#4488ff]/30`
                      : `border-[#2a2a3e] bg-[#12121a] hover:border-[#3a3a4e]`
                  }`}
                >
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs font-semibold text-[#e0e0e8]">{agent.name}</span>
                  </div>
                  <div className="flex items-center gap-1.5 mb-2">
                    <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${style.bg} ${style.text}`}>
                      {agent.role}
                    </span>
                    <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
                      agent.tier === "pro" ? "bg-violet-500/15 text-violet-400" : "bg-teal-500/15 text-teal-400"
                    }`}>
                      {agent.tier}
                    </span>
                    <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded bg-[#1a1a2e] text-[#555570] border border-[#2a2a3e] flex items-center gap-0.5">
                      {agent.integration === "sdk" ? <Cpu size={8} /> : <Network size={8} />}
                      {agent.integration}
                    </span>
                  </div>
                  {/* Pipeline check count — the key differentiator */}
                  <div className="flex items-center gap-1.5 mb-2">
                    <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded ${
                      agent.tier === "pro"
                        ? "bg-violet-500/10 text-violet-400/80"
                        : "bg-teal-500/10 text-teal-400/80"
                    }`}>
                      {agent.pipeline_check_count} pipeline checks
                    </span>
                    {agent.pro_only_checks.length > 0 && agent.tier === "pro" && (
                      <span className="text-[8px] text-violet-400/60">
                        +{agent.pro_only_checks.length} PRO
                      </span>
                    )}
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {agent.permissions.slice(0, 4).map((perm) => (
                      <span
                        key={perm}
                        className="text-[8px] font-mono px-1 py-0.5 rounded bg-[#0a0a0f] text-[#555570]"
                      >
                        {perm}
                      </span>
                    ))}
                    {agent.permissions.length > 4 && (
                      <span className="text-[8px] text-[#555570]">
                        +{agent.permissions.length - 4}
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Center — Chat */}
        {activeSession ? (
          <>
            <div className="flex-1 min-w-0">
              <ChatPanel
                sessionId={activeSession.sessionId}
                onSendMessage={handleSendMessage}
                messages={activeSession.messages}
                isLoading={isLoading}
                agentName={activeSession.agentName}
                agentRole={activeSession.agentRole}
                agentPermissions={activeSession.agentPermissions}
                tier={activeSession.tier}
                integration={activeSession.integration}
              />
            </div>

            {/* Right — Security panels */}
            <div className="w-[26rem] min-w-[26rem] flex flex-col border-l border-[#2a2a3e] bg-[#12121a]">
              {/* Security dashboard (top) */}
              <div className="h-1/2 border-b border-[#2a2a3e] overflow-auto">
                <SecurityDashboard
                  sessionId={activeSession.sessionId}
                  events={activeSession.events}
                  riskScore={activeSession.riskScore}
                  agentRole={activeSession.agentRole}
                  agentName={activeSession.agentName}
                />
              </div>

              {/* Bottom panel tabs */}
              <div className="h-1/2 flex flex-col min-h-0">
                <div className="flex border-b border-[#2a2a3e]">
                  {(["pipeline", "proof", "threat"] as const).map((tab) => (
                    <button
                      key={tab}
                      onClick={() => setActivePanel(tab)}
                      className={`flex-1 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider transition-colors ${
                        activePanel === tab
                          ? "text-[#00ff88] border-b-2 border-[#00ff88]"
                          : "text-[#555570] hover:text-[#8888a0]"
                      }`}
                    >
                      {tab === "pipeline" ? "Pipeline" : tab === "proof" ? "Proof Chain" : "Threat Intel"}
                    </button>
                  ))}
                </div>
                <div className="flex-1 min-h-0 overflow-auto">
                  {activePanel === "pipeline" && activeSession && (
                    <PipelineChecksPanel
                      checks={activeSession.pipelineChecks}
                      proOnlyChecks={activeSession.proOnlyChecks}
                      tier={activeSession.tier}
                    />
                  )}
                  {activePanel === "proof" && (
                    <ProofChainPanel
                      sessionId={activeSession.sessionId}
                      eventCount={activeSession.events.length}
                      apiBase={TESTBED_API}
                    />
                  )}
                  {activePanel === "threat" && (
                    <ThreatIntelPanel
                      sessionId={activeSession.sessionId}
                      eventCount={activeSession.events.length}
                      apiBase={TESTBED_API}
                    />
                  )}
                </div>
              </div>
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center">
              <Shield size={48} className="text-[#2a2a3e] mx-auto mb-4" />
              <p className="text-sm text-[#555570] mb-1">Select an agent to start testing</p>
              <p className="text-xs text-[#3a3a4e]">
                Each agent has different tier, integration, and permission configurations
              </p>
            </div>
          </div>
        )}
      </div>
    </main>
  );
}


/* ── Pipeline Checks Panel ─────────────────────────────────────────────── */

function PipelineChecksPanel({
  checks,
  proOnlyChecks,
  tier,
}: {
  checks: string[];
  proOnlyChecks: string[];
  tier: "free" | "pro";
}) {
  const proOnlySet = new Set(proOnlyChecks);

  return (
    <div className="p-4">
      <div className="flex items-center gap-2 mb-3">
        <ShieldCheck size={14} className={tier === "pro" ? "text-violet-400" : "text-teal-400"} />
        <span className="text-xs font-semibold text-[#8888a0] uppercase tracking-wider">
          Active Pipeline Checks
        </span>
        <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
          tier === "pro" ? "bg-violet-500/15 text-violet-400" : "bg-teal-500/15 text-teal-400"
        }`}>
          {tier} — {checks.length} checks
        </span>
      </div>

      <div className="space-y-1.5">
        {checks.map((check) => {
          const isProOnly = proOnlySet.has(check);
          const label = CHECK_LABELS[check] || check;
          return (
            <div
              key={check}
              className={`flex items-center gap-2 px-3 py-2 rounded-lg border ${
                isProOnly
                  ? "border-violet-500/30 bg-violet-500/5"
                  : "border-[#2a2a3e] bg-[#1a1a2e]"
              }`}
            >
              <div className={`w-2 h-2 rounded-full ${
                isProOnly ? "bg-violet-400 animate-pulse" : "bg-teal-400"
              }`} />
              <span className={`text-xs font-medium ${
                isProOnly ? "text-violet-300" : "text-[#e0e0e8]"
              }`}>
                {label}
              </span>
              {isProOnly && (
                <span className="text-[8px] font-bold uppercase px-1.5 py-0.5 rounded bg-violet-500/20 text-violet-400 ml-auto">
                  PRO ONLY
                </span>
              )}
            </div>
          );
        })}
      </div>

      {/* Show what FREE is missing if on PRO */}
      {tier === "pro" && proOnlyChecks.length > 0 && (
        <div className="mt-4 p-3 rounded-lg border border-violet-500/20 bg-violet-500/5">
          <div className="flex items-center gap-1.5 mb-1">
            <Zap size={10} className="text-violet-400" />
            <span className="text-[10px] font-bold text-violet-400 uppercase">
              PRO Advantage
            </span>
          </div>
          <p className="text-[10px] text-[#8888a0] leading-relaxed">
            This agent runs <span className="text-violet-300 font-bold">{proOnlyChecks.length} additional checks</span> vs FREE tier:
            {" "}{proOnlyChecks.map(c => CHECK_LABELS[c] || c).join(", ")}.
            These provide contextual AI risk analysis, data flow tracking, predictive threat modeling, and semantic drift detection.
          </p>
        </div>
      )}

      {/* Show what FREE doesn't have */}
      {tier === "free" && proOnlyChecks.length > 0 && (
        <div className="mt-4 p-3 rounded-lg border border-[#2a2a3e] bg-[#0a0a0f]">
          <div className="flex items-center gap-1.5 mb-2">
            <Lock size={10} className="text-[#555570]" />
            <span className="text-[10px] font-bold text-[#555570] uppercase">
              Not Active on FREE Tier
            </span>
          </div>
          <div className="space-y-1">
            {proOnlyChecks.map((check) => (
              <div
                key={check}
                className="flex items-center gap-2 px-3 py-1.5 rounded border border-[#2a2a3e]/50 bg-[#12121a] opacity-40"
              >
                <ShieldAlert size={10} className="text-[#555570]" />
                <span className="text-[10px] text-[#555570] line-through">
                  {CHECK_LABELS[check] || check}
                </span>
                <span className="text-[8px] font-bold uppercase px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-400/40 ml-auto">
                  PRO
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
