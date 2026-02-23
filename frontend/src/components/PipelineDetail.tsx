"use client";

import { ChevronDown, ChevronRight } from "lucide-react";
import { useState } from "react";

interface SecurityEvent {
  event_type: string;
  session_id: string;
  data: Record<string, unknown>;
  timestamp: string;
}

interface PipelineDetailProps {
  events: SecurityEvent[];
  sessionId: string | null;
}

export default function PipelineDetail({ events, sessionId }: PipelineDetailProps) {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  const latestEvent = events.length > 0 ? events[events.length - 1] : null;

  return (
    <div className="flex flex-col h-full bg-[#12121a]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Pipeline Detail
        </h2>
      </div>

      {/* Latest verdict raw data */}
      {latestEvent && (
        <div className="p-4 border-b border-[#2a2a3e]">
          <h3 className="text-xs text-[#8888a0] uppercase mb-2">Latest Verdict</h3>
          <pre className="text-[11px] text-[#00ff88] bg-[#0a0a0f] rounded-lg p-3 overflow-x-auto max-h-48 overflow-y-auto">
            {JSON.stringify(latestEvent.data, null, 2)}
          </pre>
        </div>
      )}

      {/* All events expandable list */}
      <div className="flex-1 overflow-y-auto p-4">
        <h3 className="text-xs text-[#8888a0] uppercase mb-3">All Pipeline Events</h3>
        <div className="space-y-1">
          {events.map((event, i) => (
            <div key={i} className="bg-[#1a1a2e] rounded border border-[#2a2a3e]">
              <button
                onClick={() => setExpandedIndex(expandedIndex === i ? null : i)}
                className="w-full flex items-center justify-between px-3 py-2 text-xs hover:bg-[#2a2a3e]/50"
              >
                <span className="font-mono text-[#e0e0e8]">
                  {String(event.data.tool_name || "event")} — {String(event.data.verdict || event.event_type)}
                </span>
                {expandedIndex === i ? (
                  <ChevronDown size={12} className="text-[#8888a0]" />
                ) : (
                  <ChevronRight size={12} className="text-[#8888a0]" />
                )}
              </button>
              {expandedIndex === i && (
                <pre className="text-[10px] text-[#8888a0] bg-[#0a0a0f] px-3 py-2 overflow-x-auto border-t border-[#2a2a3e]">
                  {JSON.stringify(event.data, null, 2)}
                </pre>
              )}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
