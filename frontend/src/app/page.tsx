"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import ChatPanel from "@/components/ChatPanel";
import SecurityDashboard from "@/components/SecurityDashboard";
import PipelineDetail from "@/components/PipelineDetail";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

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

export default function Home() {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [riskScore, setRiskScore] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  // Create session on mount
  useEffect(() => {
    const createSession = async () => {
      try {
        const resp = await fetch(`${API_BASE}/api/sessions`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ agent_id: "demo-agent", original_goal: "" }),
        });
        const data = await resp.json();
        setSessionId(data.session_id);
      } catch (err) {
        console.error("Failed to create session:", err);
      }
    };
    createSession();
  }, []);

  // Connect WebSocket when session is ready
  useEffect(() => {
    if (!sessionId) return;

    const wsUrl = API_BASE.replace("http", "ws");
    const ws = new WebSocket(`${wsUrl}/api/ws/session/${sessionId}`);
    wsRef.current = ws;

    ws.onmessage = (event) => {
      const secEvent: SecurityEvent = JSON.parse(event.data);
      setEvents((prev) => [...prev, secEvent]);
      if (secEvent.data.risk_score !== undefined) {
        setRiskScore(secEvent.data.risk_score as number);
      }
    };

    ws.onerror = (err) => console.error("WebSocket error:", err);

    return () => {
      ws.close();
    };
  }, [sessionId]);

  const handleSendMessage = useCallback(
    async (message: string) => {
      if (!sessionId) return;

      setMessages((prev) => [...prev, { role: "user", content: message }]);
      setIsLoading(true);

      try {
        const resp = await fetch(`${API_BASE}/api/chat`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ session_id: sessionId, message }),
        });
        const data = await resp.json();

        setMessages((prev) => [
          ...prev,
          {
            role: "assistant",
            content: data.message,
            toolCalls: data.tool_calls,
          },
        ]);
      } catch (err) {
        setMessages((prev) => [
          ...prev,
          { role: "assistant", content: "Error: Failed to get response." },
        ]);
      } finally {
        setIsLoading(false);
      }
    },
    [sessionId]
  );

  return (
    <main className="h-screen flex flex-col">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-3 border-b border-[#2a2a3e] bg-[#0a0a0f]">
        <div className="flex items-center gap-3">
          <div className="w-2 h-2 rounded-full bg-[#00ff88] animate-pulse" />
          <h1 className="text-lg font-bold text-[#e0e0e8]">Sentinel</h1>
          <span className="text-xs text-[#555570]">Autonomous Security Layer</span>
        </div>
        <div className="flex items-center gap-4 text-xs text-[#8888a0]">
          <span>Risk: <span style={{ color: riskScore >= 80 ? "#ff4444" : riskScore >= 40 ? "#ffaa00" : "#00ff88" }}>{riskScore.toFixed(1)}</span></span>
          <span>Events: {events.length}</span>
        </div>
      </header>

      {/* Three-panel layout */}
      <div className="flex-1 grid grid-cols-[35%_35%_30%] overflow-hidden">
        <ChatPanel
          sessionId={sessionId}
          onSendMessage={handleSendMessage}
          messages={messages}
          isLoading={isLoading}
        />
        <SecurityDashboard
          sessionId={sessionId}
          events={events}
          riskScore={riskScore}
        />
        <PipelineDetail events={events} sessionId={sessionId} />
      </div>
    </main>
  );
}
