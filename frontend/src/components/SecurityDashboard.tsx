"use client";

import { useState, useEffect } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";

interface SecurityEvent {
  event_type: string;
  session_id: string;
  data: {
    verdict?: string;
    risk_score?: number;
    risk_delta?: number;
    tool_name?: string;
    reasons?: string[];
    drift_score?: number;
    itdr_signals?: string[];
    recommended_action?: string;
  };
  timestamp: string;
}

interface SecurityDashboardProps {
  sessionId: string | null;
  events: SecurityEvent[];
  riskScore: number;
  agentRole?: string;
  agentName?: string;
}

const ROLE_COLORS: Record<string, { bg: string; text: string }> = {
  research: { bg: "bg-blue-500/15", text: "text-blue-400" },
  code: { bg: "bg-green-500/15", text: "text-green-400" },
  financial: { bg: "bg-amber-500/15", text: "text-amber-400" },
  communication: { bg: "bg-purple-500/15", text: "text-purple-400" },
  admin: { bg: "bg-red-500/15", text: "text-red-400" },
  data_analysis: { bg: "bg-cyan-500/15", text: "text-cyan-400" },
};

export default function SecurityDashboard({
  sessionId,
  events,
  riskScore,
  agentRole,
  agentName,
}: SecurityDashboardProps) {
  const [expandedEvents, setExpandedEvents] = useState<Set<number>>(new Set());
  const riskColor = riskScore >= 80 ? "#ff4444" : riskScore >= 60 ? "#ffaa00" : riskScore >= 40 ? "#ffaa00" : "#00ff88";
  const riskPercent = Math.min(100, riskScore);

  const toggleEvent = (index: number) => {
    setExpandedEvents((prev) => {
      const next = new Set(prev);
      if (next.has(index)) next.delete(index);
      else next.add(index);
      return next;
    });
  };

  // Auto-expand non-allow events so BLOCK/CHALLENGE reasons are immediately visible
  useEffect(() => {
    setExpandedEvents((prev) => {
      const next = new Set(prev);
      events.forEach((event, i) => {
        if (event.data.verdict && event.data.verdict !== "allow") {
          next.add(i);
        }
      });
      return next;
    });
  }, [events.length]);

  const verdictBadge = (verdict: string) => {
    const colors: Record<string, string> = {
      allow: "bg-green-500/20 text-green-400 border-green-500/30",
      block: "bg-red-500/20 text-red-400 border-red-500/30",
      challenge: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
      sandbox: "bg-blue-500/20 text-blue-400 border-blue-500/30",
      pause: "bg-purple-500/20 text-purple-400 border-purple-500/30",
    };
    return colors[verdict] || "bg-gray-500/20 text-gray-400";
  };

  const roleStyle = agentRole ? ROLE_COLORS[agentRole] || { bg: "bg-gray-500/15", text: "text-gray-400" } : null;

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#12121a] border-r border-[#2a2a3e]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Security Dashboard
        </h2>
      </div>

      {/* Risk Gauge */}
      <div className="p-4 border-b border-[#2a2a3e]">
        {agentName && agentRole && roleStyle && (
          <div className="flex items-center gap-2 mb-3">
            <span className="text-xs text-[#e0e0e8]">{agentName}</span>
            <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${roleStyle.bg} ${roleStyle.text}`}>
              {agentRole}
            </span>
          </div>
        )}
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs text-[#8888a0] uppercase">Session Risk</span>
          <span className="text-2xl font-bold" style={{ color: riskColor }}>
            {riskScore.toFixed(1)}
          </span>
        </div>
        <div className="w-full h-3 bg-[#1a1a2e] rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-500"
            style={{
              width: `${riskPercent}%`,
              backgroundColor: riskColor,
            }}
          />
        </div>
        <div className="flex justify-between text-[10px] text-[#555570] mt-1">
          <span>0 Safe</span>
          <span>40</span>
          <span>60</span>
          <span>80 Lock</span>
          <span>100</span>
        </div>
      </div>

      {/* Threat Forecast */}
      {(() => {
        const latestPrediction = [...events].reverse().find((e) =>
          e.data.reasons?.some((r: string) => r.toLowerCase().includes("threat trajectory"))
        );
        if (!latestPrediction) return null;
        const reason = latestPrediction.data.reasons?.find((r: string) => r.toLowerCase().includes("threat trajectory")) || "";
        const nameMatch = reason.match(/trajectory '([^']+)'/);
        const confMatch = reason.match(/(\d+)% confidence/);
        const trajectoryName = nameMatch ? nameMatch[1] : "Unknown";
        const confidence = confMatch ? parseInt(confMatch[1]) : 0;

        return (
          <div className="p-4 border-b border-[#2a2a3e]">
            <h3 className="text-xs text-[#8888a0] uppercase mb-2">Threat Forecast</h3>
            <div className="bg-[#1a1a2e] rounded-lg p-3 border border-amber-500/30">
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-semibold text-amber-400">
                  {trajectoryName.replace(/_/g, " ")}
                </span>
                <span className="text-[10px] text-[#8888a0]">{confidence}% confidence</span>
              </div>
              <div className="w-full h-2 bg-[#0a0a0f] rounded-full overflow-hidden mt-1">
                <div
                  className="h-full rounded-full bg-amber-500 transition-all duration-500"
                  style={{ width: `${confidence}%` }}
                />
              </div>
              <p className="text-[10px] text-[#8888a0] mt-2 italic">
                {reason}
              </p>
            </div>
          </div>
        );
      })()}

      {/* Event Timeline */}
      <div className="flex-1 overflow-y-auto p-4">
        <h3 className="text-xs text-[#8888a0] uppercase mb-3">Verdict Timeline</h3>
        {events.length === 0 ? (
          <p className="text-xs text-[#555570] italic">No events yet. Start chatting to see security verdicts.</p>
        ) : (
          <div className="space-y-3">
            {events.map((event, i) => {
              const hasDetails = Boolean(
                (event.data.reasons && event.data.reasons.length > 0) ||
                (event.data.itdr_signals && event.data.itdr_signals.length > 0) ||
                event.data.recommended_action ||
                (event.data as Record<string, unknown>).integration
              );
              const isExpanded = expandedEvents.has(i);
              return (
                <div
                  key={i}
                  className={`bg-[#1a1a2e] rounded-lg p-3 border transition-colors ${
                    isExpanded ? "border-[#3a3a5e]" : "border-[#2a2a3e]"
                  }`}
                >
                  <div
                    className="flex items-center justify-between mb-1 cursor-pointer"
                    onClick={() => hasDetails && toggleEvent(i)}
                    role={hasDetails ? "button" : undefined}
                  >
                    <div className="flex items-center gap-1.5">
                      {hasDetails && (
                        isExpanded
                          ? <ChevronDown size={10} className="text-[#555570]" />
                          : <ChevronRight size={10} className="text-[#555570]" />
                      )}
                      <span className="text-xs font-mono text-[#e0e0e8]">
                        {event.data.tool_name || "unknown"}
                      </span>
                      {String((event.data as Record<string, unknown>).integration || "") !== "" && (
                        <span className="text-[8px] font-bold uppercase px-1 py-0.5 rounded bg-[#0a0a0f] text-[#555570] border border-[#2a2a3e]">
                          {String((event.data as Record<string, unknown>).integration)}
                        </span>
                      )}
                    </div>
                    <span
                      className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${verdictBadge(event.data.verdict || "")}`}
                    >
                      {event.data.verdict}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-[#8888a0]">
                    <span>Risk: {event.data.risk_score?.toFixed(1)}</span>
                    <span>Delta: +{event.data.risk_delta?.toFixed(1)}</span>
                    {event.data.drift_score ? (
                      <span className="text-amber-400">Drift: {event.data.drift_score.toFixed(2)}</span>
                    ) : null}
                  </div>
                  {!isExpanded && event.data.reasons && event.data.reasons.length > 0 && (
                    <p className="text-[10px] text-[#8888a0] mt-1 truncate">
                      {event.data.reasons[0]}
                    </p>
                  )}
                  {isExpanded && (
                    <div className="mt-2 space-y-1.5 border-t border-[#2a2a3e] pt-2">
                      {event.data.reasons && event.data.reasons.map((reason, j) => (
                        <p key={j} className="text-[10px] text-[#b0b0c0] leading-relaxed">
                          <span className="text-[#555570] mr-1">{j + 1}.</span>
                          {reason}
                        </p>
                      ))}
                      {event.data.itdr_signals && event.data.itdr_signals.length > 0 && (
                        <div className="mt-1">
                          <span className="text-[9px] text-[#555570] uppercase font-bold">ITDR Signals</span>
                          {event.data.itdr_signals.map((sig, j) => (
                            <p key={j} className="text-[10px] text-orange-400/80 ml-2">{sig}</p>
                          ))}
                        </div>
                      )}
                      {event.data.recommended_action && (
                        <div className="mt-1">
                          <span className="text-[9px] text-[#555570] uppercase font-bold">Action: </span>
                          <span className="text-[10px] text-[#b0b0c0]">{event.data.recommended_action}</span>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
