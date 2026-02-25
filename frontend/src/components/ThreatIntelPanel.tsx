"use client";

import { useState, useEffect } from "react";
import { apiFetch } from "@/lib/api";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ThreatPattern {
  pattern_id: string;
  pattern_type: string;
  tool_sequence: string[];
  risk_contribution: number;
  confidence: number;
  first_seen: string;
  times_seen: number;
  source: string;
}

interface ThreatIntelStats {
  total_patterns: number;
  built_in_count: number;
  learned_count: number;
  total_matches: number;
}

interface ThreatIntelPanelProps {
  sessionId: string;
  eventCount: number;
  apiBase?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  data_exfiltration: "border-red-500/40",
  data_exfiltration_via_db: "border-red-500/40",
  privilege_escalation: "border-orange-500/40",
  credential_theft: "border-red-500/40",
  financial_fraud: "border-amber-500/40",
  recon_exploit: "border-yellow-500/40",
};

export default function ThreatIntelPanel({ eventCount, apiBase }: ThreatIntelPanelProps) {
  const baseUrl = apiBase || API_BASE;
  const [patterns, setPatterns] = useState<ThreatPattern[]>([]);
  const [stats, setStats] = useState<ThreatIntelStats | null>(null);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [pResp, sResp] = await Promise.all([
          apiFetch(`${baseUrl}/api/threat-intel`),
          apiFetch(`${baseUrl}/api/threat-intel/stats`),
        ]);
        const pData = await pResp.json();
        setPatterns(Array.isArray(pData) ? pData : []);
        setStats(await sResp.json());
      } catch (err) {
        console.error("Failed to fetch threat intel:", err);
      }
    };
    fetchData();
  }, [eventCount]);

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#12121a]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Threat Intelligence
        </h2>
      </div>

      {/* Stats header */}
      {stats && (
        <div className="px-4 py-2 border-b border-[#2a2a3e] flex items-center gap-4">
          <span className="text-[10px] text-[#8888a0]">
            Patterns: <span className="text-[#e0e0e8] font-mono">{stats.total_patterns}</span>
          </span>
          <span className="text-[10px] text-[#8888a0]">
            Matches: <span className="text-[#e0e0e8] font-mono">{stats.total_matches}</span>
          </span>
          {stats.learned_count > 0 && (
            <span className="text-[10px] text-amber-400 font-bold">
              +{stats.learned_count} learned
            </span>
          )}
        </div>
      )}

      {/* Pattern list */}
      <div className="flex-1 overflow-y-auto p-4">
        {patterns.length === 0 ? (
          <p className="text-xs text-[#555570] italic">Loading threat patterns...</p>
        ) : (
          <div className="space-y-3">
            {patterns.map((p) => {
              const borderColor = SEVERITY_COLORS[p.pattern_type] || "border-[#2a2a3e]";
              return (
                <div key={p.pattern_id} className={`rounded-lg border-2 ${borderColor} bg-[#1a1a2e] p-3`}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-semibold text-[#e0e0e8]">
                      {p.pattern_type.replace(/_/g, " ")}
                    </span>
                    <span className={`text-[9px] font-bold uppercase px-1.5 py-0.5 rounded ${
                      p.source === "learned" ? "bg-amber-500/20 text-amber-400" : "bg-blue-500/20 text-blue-400"
                    }`}>
                      {p.source}
                    </span>
                  </div>

                  {/* Tool sequence */}
                  <div className="flex items-center gap-1 mt-1.5 flex-wrap">
                    {p.tool_sequence.map((tool, i) => (
                      <span key={i} className="flex items-center gap-1">
                        <span className="text-[10px] font-mono text-[#8888a0] bg-[#0a0a0f] px-1.5 py-0.5 rounded">
                          {tool}
                        </span>
                        {i < p.tool_sequence.length - 1 && (
                          <span className="text-[#555570] text-[10px]">&rarr;</span>
                        )}
                      </span>
                    ))}
                  </div>

                  {/* Stats row */}
                  <div className="flex items-center gap-3 mt-2 text-[10px] text-[#8888a0]">
                    <span>Confidence: {(p.confidence * 100).toFixed(0)}%</span>
                    <span>Seen: {p.times_seen}x</span>
                    <span>Risk: +{p.risk_contribution.toFixed(0)}</span>
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
