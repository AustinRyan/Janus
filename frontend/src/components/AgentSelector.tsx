"use client";

import { Shield, Lock, Unlock } from "lucide-react";

interface AgentInfo {
  agent_id: string;
  name: string;
  role: string;
  permissions: string[];
  is_locked: boolean;
}

interface AgentSelectorProps {
  agents: AgentInfo[];
  onSelectAgent: (agentId: string) => void;
}

const ROLE_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  research: { bg: "bg-blue-500/15", text: "text-blue-400", border: "border-blue-500/30" },
  code: { bg: "bg-green-500/15", text: "text-green-400", border: "border-green-500/30" },
  financial: { bg: "bg-amber-500/15", text: "text-amber-400", border: "border-amber-500/30" },
  communication: { bg: "bg-purple-500/15", text: "text-purple-400", border: "border-purple-500/30" },
  admin: { bg: "bg-red-500/15", text: "text-red-400", border: "border-red-500/30" },
  data_analysis: { bg: "bg-cyan-500/15", text: "text-cyan-400", border: "border-cyan-500/30" },
  custom: { bg: "bg-gray-500/15", text: "text-gray-400", border: "border-gray-500/30" },
};

function getRoleStyle(role: string) {
  return ROLE_COLORS[role] || ROLE_COLORS.custom;
}

export default function AgentSelector({ agents, onSelectAgent }: AgentSelectorProps) {
  return (
    <div className="flex flex-col items-center justify-center h-full bg-[#0a0a0f] p-8">
      <div className="flex items-center gap-3 mb-2">
        <Shield size={28} className="text-[#00ff88]" />
        <h2 className="text-2xl font-bold text-[#e0e0e8]">Select an Agent</h2>
      </div>
      <p className="text-sm text-[#555570] mb-8">
        Choose an agent persona to start a security-monitored session
      </p>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 max-w-4xl w-full">
        {agents.map((agent) => {
          const style = getRoleStyle(agent.role);
          return (
            <div
              key={agent.agent_id}
              className={`relative rounded-xl border ${style.border} bg-[#12121a] p-5 transition-all hover:scale-[1.02] hover:shadow-lg hover:shadow-black/30`}
            >
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-[#e0e0e8]">{agent.name}</h3>
                {agent.is_locked ? (
                  <Lock size={14} className="text-red-400" />
                ) : (
                  <Unlock size={14} className="text-green-400/60" />
                )}
              </div>

              <span
                className={`inline-block text-[10px] font-bold uppercase px-2 py-0.5 rounded ${style.bg} ${style.text} mb-3`}
              >
                {agent.role}
              </span>

              <div className="flex flex-wrap gap-1 mb-4">
                {agent.permissions.map((perm) => (
                  <span
                    key={perm}
                    className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#1a1a2e] text-[#8888a0] border border-[#2a2a3e]"
                  >
                    {perm}
                  </span>
                ))}
              </div>

              <button
                onClick={() => onSelectAgent(agent.agent_id)}
                disabled={agent.is_locked}
                className={`w-full text-xs font-medium py-2 rounded-lg transition-colors ${
                  agent.is_locked
                    ? "bg-[#1a1a2e] text-[#555570] cursor-not-allowed"
                    : `${style.bg} ${style.text} hover:opacity-80`
                }`}
              >
                {agent.is_locked ? "Locked" : "Start Session"}
              </button>
            </div>
          );
        })}
      </div>
    </div>
  );
}
