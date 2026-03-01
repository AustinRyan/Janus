"use client";

import type { HealthFull, Session } from "./MonitorPage";

interface Props {
  health: HealthFull | null;
  sessions: Session[];
  eventCount: number;
  blockedCount: number;
  pendingApprovals?: number;
}

function Stat({
  label,
  value,
  color = "text-[#e0e0e8]",
  sub,
}: {
  label: string;
  value: string | number;
  color?: string;
  sub?: string;
}) {
  return (
    <div className="flex flex-col gap-0.5 px-4 py-3 first:pl-0">
      <span className="text-[10px] uppercase tracking-widest text-[#555570]">
        {label}
      </span>
      <span className={`font-mono text-lg font-semibold leading-none ${color}`}>
        {value}
      </span>
      {sub && (
        <span className="text-[10px] font-mono text-[#555570]">{sub}</span>
      )}
    </div>
  );
}

export function StatsBar({ health, sessions, eventCount, blockedCount, pendingApprovals = 0 }: Props) {
  const activeSessions = sessions.length;
  const maxRisk = sessions.length
    ? Math.max(...sessions.map((s) => s.risk_score))
    : 0;

  const cbState = health?.circuit_breaker ?? "closed";
  const cbColor =
    cbState === "open"
      ? "text-red-400"
      : cbState === "half_open"
        ? "text-amber-400"
        : "text-emerald-400";

  const statusColor = health?.status === "ok" ? "text-emerald-400" : "text-red-400";

  return (
    <div className="mb-6 flex flex-wrap items-stretch divide-x divide-[#2a2a3e] rounded-xl border border-[#2a2a3e] bg-[#12121a]/80 backdrop-blur-sm">
      <Stat label="Total Events" value={eventCount} />
      <Stat
        label="Blocked"
        value={blockedCount}
        color={blockedCount > 0 ? "text-red-400" : "text-[#555570]"}
      />
      <Stat
        label="Pending Approvals"
        value={pendingApprovals}
        color={pendingApprovals > 0 ? "text-orange-400" : "text-[#555570]"}
      />
      <Stat
        label="Status"
        value={health?.status?.toUpperCase() ?? "---"}
        color={statusColor}
      />
      <Stat
        label="Circuit Breaker"
        value={cbState.toUpperCase()}
        color={cbColor}
      />
      <Stat
        label="Avg Latency"
        value={health ? `${health.avg_latency_ms.toFixed(0)}ms` : "---"}
        sub={health ? `p95: ${health.p95_latency_ms.toFixed(0)}ms` : undefined}
      />
      <Stat
        label="Active Sessions"
        value={activeSessions}
      />
      <Stat
        label="Peak Risk"
        value={maxRisk.toFixed(1)}
        color={
          maxRisk >= 80
            ? "text-red-400"
            : maxRisk >= 60
              ? "text-orange-400"
              : maxRisk >= 40
                ? "text-amber-400"
                : "text-emerald-400"
        }
      />
      <Stat
        label="Error Rate"
        value={health ? `${(health.error_rate * 100).toFixed(1)}%` : "---"}
        color={
          health && health.error_rate > 0.1
            ? "text-red-400"
            : "text-[#e0e0e8]"
        }
      />
    </div>
  );
}
