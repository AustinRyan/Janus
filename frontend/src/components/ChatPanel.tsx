"use client";

import { useState, useRef, useEffect } from "react";
import { Send } from "lucide-react";

interface Message {
  role: "user" | "assistant";
  content: string;
  toolCalls?: ToolCall[];
}

interface ToolCall {
  tool_name: string;
  verdict: string;
  risk_score: number;
  risk_delta: number;
}

interface ChatPanelProps {
  sessionId: string | null;
  onSendMessage: (message: string) => Promise<void>;
  messages: Message[];
  isLoading: boolean;
  agentName?: string;
  agentRole?: string;
  agentPermissions?: string[];
  tier?: "free" | "pro";
  integration?: "sdk" | "mcp";
}

const ROLE_COLORS: Record<string, { bg: string; text: string }> = {
  research: { bg: "bg-blue-500/15", text: "text-blue-400" },
  code: { bg: "bg-green-500/15", text: "text-green-400" },
  financial: { bg: "bg-amber-500/15", text: "text-amber-400" },
  communication: { bg: "bg-purple-500/15", text: "text-purple-400" },
  admin: { bg: "bg-red-500/15", text: "text-red-400" },
  data_analysis: { bg: "bg-cyan-500/15", text: "text-cyan-400" },
};

export default function ChatPanel({
  sessionId,
  onSendMessage,
  messages,
  isLoading,
  agentName,
  agentRole,
  agentPermissions,
  tier,
  integration,
}: ChatPanelProps) {
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim() || isLoading) return;
    const msg = input;
    setInput("");
    await onSendMessage(msg);
  };

  const verdictColor = (verdict: string) => {
    switch (verdict) {
      case "allow": return "text-green-400 bg-green-400/10";
      case "block": return "text-red-400 bg-red-400/10";
      case "challenge": return "text-yellow-400 bg-yellow-400/10";
      case "sandbox": return "text-blue-400 bg-blue-400/10";
      case "pause": return "text-purple-400 bg-purple-400/10";
      default: return "text-gray-400 bg-gray-400/10";
    }
  };

  const roleStyle = agentRole ? ROLE_COLORS[agentRole] || { bg: "bg-gray-500/15", text: "text-gray-400" } : null;

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#12121a] border-r border-[#2a2a3e]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Agent Chat
        </h2>
        {agentName && agentRole && roleStyle && (
          <div className="flex items-center gap-2 mt-1">
            <span className="text-xs text-[#e0e0e8] font-medium">{agentName}</span>
            <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${roleStyle.bg} ${roleStyle.text}`}>
              {agentRole}
            </span>
            {tier && (
              <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                tier === "pro" ? "bg-violet-500/15 text-violet-400" : "bg-teal-500/15 text-teal-400"
              }`}>
                {tier}
              </span>
            )}
            {integration && (
              <span className="text-[10px] font-bold uppercase px-1.5 py-0.5 rounded bg-[#1a1a2e] text-[#8888a0] border border-[#2a2a3e]">
                {integration}
              </span>
            )}
          </div>
        )}
        {agentPermissions && agentPermissions.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1.5">
            {agentPermissions.map((perm) => (
              <span
                key={perm}
                className="text-[9px] font-mono px-1 py-0.5 rounded bg-[#1a1a2e] text-[#555570] border border-[#2a2a3e]"
              >
                {perm}
              </span>
            ))}
          </div>
        )}
        {sessionId && !agentName && (
          <span className="text-xs text-[#555570]">{sessionId}</span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[85%] rounded-lg px-3 py-2 text-sm ${
                msg.role === "user"
                  ? "bg-[#4488ff]/20 text-blue-100"
                  : "bg-[#1a1a2e] text-[#e0e0e8]"
              }`}
            >
              <p className="whitespace-pre-wrap">{msg.content}</p>
              {msg.toolCalls && msg.toolCalls.length > 0 && (
                <div className="mt-2 space-y-1">
                  {msg.toolCalls.map((tc, j) => (
                    <div
                      key={j}
                      className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-mono ${verdictColor(tc.verdict)}`}
                    >
                      <span>{tc.tool_name}</span>
                      <span className="font-bold uppercase">{tc.verdict}</span>
                      <span className="opacity-60">+{tc.risk_delta.toFixed(1)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="flex justify-start">
            <div className="bg-[#1a1a2e] rounded-lg px-3 py-2 text-sm text-[#8888a0]">
              <span className="animate-pulse">Thinking...</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      <form onSubmit={handleSubmit} className="p-3 border-t border-[#2a2a3e]">
        <div className="flex gap-2">
          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={sessionId ? "Type a message..." : "Start a session first..."}
            disabled={!sessionId || isLoading}
            className="flex-1 bg-[#1a1a2e] border border-[#2a2a3e] rounded-lg px-3 py-2 text-sm text-[#e0e0e8] placeholder-[#555570] focus:outline-none focus:border-[#4488ff]"
          />
          <button
            type="submit"
            disabled={!sessionId || isLoading || !input.trim()}
            className="bg-[#4488ff] hover:bg-[#3377ee] disabled:opacity-30 rounded-lg px-3 py-2 text-white"
          >
            <Send size={16} />
          </button>
        </div>
      </form>
    </div>
  );
}
