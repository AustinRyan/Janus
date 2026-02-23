"use client";

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
}

export default function SecurityDashboard({
  sessionId,
  events,
  riskScore,
}: SecurityDashboardProps) {
  const riskColor = riskScore >= 80 ? "#ff4444" : riskScore >= 60 ? "#ffaa00" : riskScore >= 40 ? "#ffaa00" : "#00ff88";
  const riskPercent = Math.min(100, riskScore);

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

  return (
    <div className="flex flex-col h-full bg-[#12121a] border-r border-[#2a2a3e]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Security Dashboard
        </h2>
      </div>

      {/* Risk Gauge */}
      <div className="p-4 border-b border-[#2a2a3e]">
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

      {/* Event Timeline */}
      <div className="flex-1 overflow-y-auto p-4">
        <h3 className="text-xs text-[#8888a0] uppercase mb-3">Verdict Timeline</h3>
        {events.length === 0 ? (
          <p className="text-xs text-[#555570] italic">No events yet. Start chatting to see security verdicts.</p>
        ) : (
          <div className="space-y-3">
            {events.map((event, i) => (
              <div key={i} className="bg-[#1a1a2e] rounded-lg p-3 border border-[#2a2a3e]">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-mono text-[#e0e0e8]">
                    {event.data.tool_name || "unknown"}
                  </span>
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
                    <span>Drift: {event.data.drift_score.toFixed(2)}</span>
                  ) : null}
                </div>
                {event.data.reasons && event.data.reasons.length > 0 && (
                  <p className="text-[10px] text-[#8888a0] mt-1 truncate">
                    {event.data.reasons[0]}
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
