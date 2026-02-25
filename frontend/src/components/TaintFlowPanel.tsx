"use client";

interface SecurityEvent {
  event_type: string;
  session_id: string;
  data: {
    verdict?: string;
    risk_score?: number;
    risk_delta?: number;
    tool_name?: string;
    tool_input?: Record<string, unknown>;
    reasons?: string[];
    recommended_action?: string;
  };
  timestamp: string;
}

interface TaintFlowPanelProps {
  events: SecurityEvent[];
  sessionId: string;
}

const SINK_TOOLS = new Set([
  "send_email", "send_message", "api_call",
  "financial_transfer", "write_file",
]);

const TAINT_COLORS: Record<string, { bg: string; text: string }> = {
  pii: { bg: "bg-orange-500/20", text: "text-orange-400" },
  credentials: { bg: "bg-red-500/20", text: "text-red-400" },
  financial: { bg: "bg-amber-500/20", text: "text-amber-400" },
  internal: { bg: "bg-blue-500/20", text: "text-blue-400" },
  source_code: { bg: "bg-purple-500/20", text: "text-purple-400" },
};

function extractTaintLabels(reasons: string[]): string[] {
  const labels: string[] = [];
  for (const reason of reasons) {
    const lower = reason.toLowerCase();
    if (lower.includes("pii")) labels.push("pii");
    if (lower.includes("credentials")) labels.push("credentials");
    if (lower.includes("financial") && lower.includes("taint")) labels.push("financial");
    if (lower.includes("internal")) labels.push("internal");
  }
  return [...new Set(labels)];
}

export default function TaintFlowPanel({ events }: TaintFlowPanelProps) {
  const toolEvents = events.filter((e) => e.data.tool_name);

  // Track accumulated taints across events
  const activeTaints = new Set<string>();
  const eventTaints: Map<number, string[]> = new Map();

  toolEvents.forEach((event, i) => {
    const reasons = event.data.reasons || [];
    const labels = extractTaintLabels(reasons);
    labels.forEach((l) => activeTaints.add(l));
    if (labels.length > 0) {
      eventTaints.set(i, labels);
    }
  });

  const taintViolations = toolEvents.filter(
    (e) => e.data.reasons?.some((r) => r.toLowerCase().includes("taint")) && e.data.verdict === "block"
  );

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#12121a] border-r border-[#2a2a3e]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Data Flow / Taint Tracking
        </h2>
      </div>

      {/* Active Taints Header */}
      <div className="px-4 py-2 border-b border-[#2a2a3e] flex items-center gap-2 flex-wrap">
        <span className="text-[10px] text-[#8888a0] uppercase">Active Taints:</span>
        {activeTaints.size === 0 ? (
          <span className="text-[10px] text-[#555570]">None</span>
        ) : (
          [...activeTaints].map((label) => {
            const color = TAINT_COLORS[label] || { bg: "bg-gray-500/20", text: "text-gray-400" };
            return (
              <span key={label} className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${color.bg} ${color.text}`}>
                {label}
              </span>
            );
          })
        )}
        {taintViolations.length > 0 && (
          <span className="text-[10px] text-red-400 font-bold ml-auto">
            {taintViolations.length} blocked
          </span>
        )}
      </div>

      {/* Flow Diagram */}
      <div className="flex-1 overflow-y-auto p-4">
        {toolEvents.length === 0 ? (
          <p className="text-xs text-[#555570] italic">
            No tool calls yet. Data flow will appear here.
          </p>
        ) : (
          <div className="space-y-0">
            {toolEvents.map((event, i) => {
              const isSink = SINK_TOOLS.has(event.data.tool_name || "");
              const isBlocked = event.data.verdict === "block";
              const isTaintBlock = isBlocked && event.data.reasons?.some((r) => r.toLowerCase().includes("taint"));
              const labels = eventTaints.get(i) || [];

              const borderColor = isBlocked
                ? "border-red-500/60"
                : isSink
                ? "border-amber-500/40"
                : "border-green-500/30";

              return (
                <div key={i}>
                  {/* Connector line */}
                  {i > 0 && (
                    <div className="flex justify-center">
                      <div className={`w-px h-6 ${isTaintBlock ? "bg-red-500 animate-pulse" : activeTaints.size > 0 ? "bg-amber-500/50" : "bg-[#2a2a3e]"}`} />
                    </div>
                  )}

                  {/* Node */}
                  <div className={`rounded-lg border-2 ${borderColor} bg-[#1a1a2e] p-3 ${isTaintBlock ? "animate-pulse" : ""}`}>
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-[#e0e0e8]">
                        #{i + 1} {event.data.tool_name}
                      </span>
                      <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                        isBlocked ? "bg-red-500/20 text-red-400" : "bg-green-500/20 text-green-400"
                      }`}>
                        {event.data.verdict}
                      </span>
                    </div>

                    {/* Taint labels */}
                    {labels.length > 0 && (
                      <div className="flex gap-1 mt-1.5">
                        {labels.map((label) => {
                          const color = TAINT_COLORS[label] || { bg: "bg-gray-500/20", text: "text-gray-400" };
                          return (
                            <span key={label} className={`text-[9px] font-bold uppercase px-1 py-0.5 rounded ${color.bg} ${color.text}`}>
                              {label}
                            </span>
                          );
                        })}
                      </div>
                    )}

                    {isTaintBlock && (
                      <p className="text-[10px] text-red-400 mt-1 font-semibold">
                        BLOCKED — tainted data export prevented
                      </p>
                    )}

                    {isSink && !isBlocked && activeTaints.size > 0 && (
                      <p className="text-[10px] text-amber-400 mt-1">
                        Sink tool — monitoring for taint
                      </p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
