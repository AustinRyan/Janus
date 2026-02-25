"use client";

import { X, Plus } from "lucide-react";

interface SessionInfo {
  sessionId: string;
  agentId: string;
  agentName: string;
  agentRole: string;
  riskScore: number;
  tier?: "free" | "pro";
  integration?: "sdk" | "mcp";
}

interface SessionSidebarProps {
  sessions: SessionInfo[];
  activeSessionId: string | null;
  onSelectSession: (sessionId: string) => void;
  onCloseSession: (sessionId: string) => void;
  onNewSession: () => void;
}

const ROLE_COLORS: Record<string, string> = {
  research: "text-blue-400",
  code: "text-green-400",
  financial: "text-amber-400",
  communication: "text-purple-400",
  admin: "text-red-400",
  data_analysis: "text-cyan-400",
};

function riskBadgeColor(score: number): string {
  if (score >= 80) return "bg-red-500/20 text-red-400";
  if (score >= 60) return "bg-orange-500/20 text-orange-400";
  if (score >= 40) return "bg-yellow-500/20 text-yellow-400";
  return "bg-green-500/20 text-green-400";
}

export default function SessionSidebar({
  sessions,
  activeSessionId,
  onSelectSession,
  onCloseSession,
  onNewSession,
}: SessionSidebarProps) {
  // Group sessions by agent name
  const grouped = sessions.reduce<Record<string, SessionInfo[]>>((acc, s) => {
    const key = s.agentName;
    if (!acc[key]) acc[key] = [];
    acc[key].push(s);
    return acc;
  }, {});

  return (
    <div className="flex flex-col h-full bg-[#0a0a0f] border-r border-[#2a2a3e] w-56 min-w-[14rem]">
      <div className="px-3 py-3 border-b border-[#2a2a3e] flex items-center justify-between">
        <span className="text-xs font-semibold text-[#8888a0] uppercase tracking-wider">
          Sessions
        </span>
        <button
          onClick={onNewSession}
          className="flex items-center gap-1 text-[10px] text-[#00ff88] hover:text-[#00cc66] transition-colors"
        >
          <Plus size={12} />
          New
        </button>
      </div>

      <div className="flex-1 overflow-y-auto py-2">
        {sessions.length === 0 ? (
          <p className="text-[10px] text-[#555570] italic px-3 py-2">
            No active sessions
          </p>
        ) : (
          Object.entries(grouped).map(([agentName, agentSessions]) => (
            <div key={agentName} className="mb-2">
              <div className="px-3 py-1 flex items-center gap-1.5">
                <span
                  className={`text-[10px] font-bold uppercase ${
                    ROLE_COLORS[agentSessions[0]?.agentRole] || "text-gray-400"
                  }`}
                >
                  {agentName}
                </span>
                {agentSessions[0]?.tier && (
                  <span className={`text-[8px] font-bold uppercase px-1 py-0.5 rounded ${
                    agentSessions[0].tier === "pro" ? "bg-violet-500/15 text-violet-400" : "bg-teal-500/15 text-teal-400"
                  }`}>
                    {agentSessions[0].tier}
                  </span>
                )}
                {agentSessions[0]?.integration && (
                  <span className="text-[8px] font-bold uppercase px-1 py-0.5 rounded bg-[#1a1a2e] text-[#555570] border border-[#2a2a3e]">
                    {agentSessions[0].integration}
                  </span>
                )}
              </div>
              {agentSessions.map((session) => (
                <div
                  key={session.sessionId}
                  onClick={() => onSelectSession(session.sessionId)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => { if (e.key === "Enter") onSelectSession(session.sessionId); }}
                  className={`w-full text-left px-3 py-2 flex items-center justify-between group transition-colors cursor-pointer ${
                    session.sessionId === activeSessionId
                      ? "bg-[#1a1a2e] border-l-2 border-[#4488ff]"
                      : "hover:bg-[#12121a] border-l-2 border-transparent"
                  }`}
                >
                  <div className="flex flex-col min-w-0">
                    <span className="text-[10px] font-mono text-[#8888a0] truncate">
                      {session.sessionId}
                    </span>
                    <span
                      className={`text-[10px] font-bold px-1.5 py-0.5 rounded w-fit mt-0.5 ${riskBadgeColor(
                        session.riskScore
                      )}`}
                    >
                      {session.riskScore.toFixed(1)}
                    </span>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onCloseSession(session.sessionId);
                    }}
                    className="opacity-0 group-hover:opacity-100 text-[#555570] hover:text-red-400 transition-all p-0.5"
                  >
                    <X size={12} />
                  </button>
                </div>
              ))}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
