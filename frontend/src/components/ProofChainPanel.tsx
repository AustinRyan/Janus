"use client";

import { useState, useEffect } from "react";
import { apiFetch } from "@/lib/api";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface ProofNode {
  node_id: string;
  parent_hash: string;
  step: number;
  timestamp: string;
  session_id: string;
  agent_id: string;
  tool_name: string;
  verdict: string;
  risk_score: number;
  risk_delta: number;
  content_hash: string;
}

interface ProofChainPanelProps {
  sessionId: string;
  eventCount: number; // triggers re-fetch when events arrive
  apiBase?: string;
}

export default function ProofChainPanel({ sessionId, eventCount, apiBase }: ProofChainPanelProps) {
  const baseUrl = apiBase || API_BASE;
  const [chain, setChain] = useState<ProofNode[]>([]);
  const [verified, setVerified] = useState<boolean | null>(null);
  const [verifying, setVerifying] = useState(false);

  useEffect(() => {
    const fetchChain = async () => {
      try {
        const resp = await apiFetch(`${baseUrl}/api/sessions/${sessionId}/proof`);
        const data = await resp.json();
        setChain(Array.isArray(data) ? data : []);
        setVerified(null);
      } catch (err) {
        console.error("Failed to fetch proof chain:", err);
      }
    };
    fetchChain();
  }, [sessionId, eventCount]);

  const handleVerify = async () => {
    setVerifying(true);
    try {
      const resp = await apiFetch(`${baseUrl}/api/sessions/${sessionId}/proof/verify`, { method: "POST" });
      const data = await resp.json();
      setVerified(data.valid);
    } catch {
      setVerified(false);
    } finally {
      setVerifying(false);
    }
  };

  const handleExport = () => {
    const blob = new Blob([JSON.stringify(chain, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `proof-chain-${sessionId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-full min-h-0 bg-[#12121a]">
      <div className="px-4 py-3 border-b border-[#2a2a3e]">
        <h2 className="text-sm font-semibold text-[#8888a0] uppercase tracking-wider">
          Proof Chain
        </h2>
      </div>

      {/* Header stats + actions */}
      <div className="px-4 py-2 border-b border-[#2a2a3e] flex items-center justify-between">
        <div className="flex items-center gap-3">
          <span className="text-[10px] text-[#8888a0]">
            Length: <span className="text-[#e0e0e8] font-mono">{chain.length}</span>
          </span>
          {verified !== null && (
            <span className={`text-[10px] font-bold ${verified ? "text-green-400" : "text-red-400"}`}>
              {verified ? "Verified" : "TAMPERED"}
            </span>
          )}
        </div>
        <div className="flex gap-2">
          <button
            onClick={handleVerify}
            disabled={verifying || chain.length === 0}
            className="text-[10px] px-2 py-1 rounded bg-[#1a1a2e] border border-[#2a2a3e] text-[#8888a0] hover:text-[#00ff88] hover:border-[#00ff88]/30 disabled:opacity-50 transition-colors"
          >
            {verifying ? "Verifying..." : "Verify"}
          </button>
          <button
            onClick={handleExport}
            disabled={chain.length === 0}
            className="text-[10px] px-2 py-1 rounded bg-[#1a1a2e] border border-[#2a2a3e] text-[#8888a0] hover:text-[#00ff88] hover:border-[#00ff88]/30 disabled:opacity-50 transition-colors"
          >
            Export
          </button>
        </div>
      </div>

      {/* Chain visualization */}
      <div className="flex-1 overflow-y-auto p-4">
        {chain.length === 0 ? (
          <p className="text-xs text-[#555570] italic">
            No proof nodes yet. Each tool call creates a cryptographically linked node.
          </p>
        ) : (
          <div className="space-y-0">
            {[...chain].reverse().map((node, i) => (
              <div key={node.node_id}>
                {i > 0 && (
                  <div className="flex justify-center">
                    <div className="w-px h-4 bg-[#00ff88]/30" />
                  </div>
                )}
                <div className="rounded-lg border border-[#2a2a3e] bg-[#1a1a2e] p-3">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-mono text-[#e0e0e8]">
                      #{node.step} {node.tool_name}
                    </span>
                    <span className={`text-[10px] font-bold uppercase px-1.5 py-0.5 rounded ${
                      node.verdict === "block" ? "bg-red-500/20 text-red-400"
                        : node.verdict === "allow" ? "bg-green-500/20 text-green-400"
                        : "bg-yellow-500/20 text-yellow-400"
                    }`}>
                      {node.verdict}
                    </span>
                  </div>
                  <div className="text-[10px] text-[#555570] font-mono space-y-0.5">
                    <div>hash: {node.node_id.slice(0, 16)}...{node.node_id.slice(-8)}</div>
                    {node.parent_hash && (
                      <div>parent: {node.parent_hash.slice(0, 16)}...{node.parent_hash.slice(-8)}</div>
                    )}
                  </div>
                  <div className="flex items-center gap-3 mt-1 text-[10px] text-[#8888a0]">
                    <span>Risk: {node.risk_score.toFixed(1)}</span>
                    <span>Delta: +{node.risk_delta.toFixed(1)}</span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
