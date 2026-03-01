"use client";

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  ReferenceLine,
  ResponsiveContainer,
  Tooltip,
} from "recharts";
import type { RiskEvent } from "./MonitorPage";

interface Props {
  events: RiskEvent[];
}

export function RiskTimeline({ events }: Props) {
  const data = events.map((e, i) => ({
    index: i + 1,
    risk: e.new_score,
    tool: e.tool_name,
    delta: e.risk_delta,
  }));

  if (data.length === 0) {
    return (
      <div className="flex h-[200px] items-center justify-center rounded-xl border border-[#2a2a3e] bg-[#12121a]/80 text-sm text-[#555570]">
        No risk events yet
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-[#2a2a3e] bg-[#12121a]/80 p-4">
      <h3 className="mb-3 text-xs font-semibold uppercase tracking-widest text-[#555570]">
        Risk Timeline
      </h3>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
          <defs>
            <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#00ff88" stopOpacity={0.25} />
              <stop offset="100%" stopColor="#00ff88" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="index"
            tick={{ fill: "#555570", fontSize: 10 }}
            axisLine={{ stroke: "#2a2a3e" }}
            tickLine={false}
          />
          <YAxis
            domain={[0, 100]}
            tick={{ fill: "#555570", fontSize: 10 }}
            axisLine={{ stroke: "#2a2a3e" }}
            tickLine={false}
          />
          <ReferenceLine
            y={50}
            stroke="#ffaa00"
            strokeDasharray="4 4"
            strokeOpacity={0.5}
            label={{ value: "Sandbox", fill: "#ffaa0080", fontSize: 9, position: "right" }}
          />
          <ReferenceLine
            y={80}
            stroke="#ff4444"
            strokeDasharray="4 4"
            strokeOpacity={0.5}
            label={{ value: "Lock", fill: "#ff444480", fontSize: 9, position: "right" }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: "#1a1a2e",
              border: "1px solid #2a2a3e",
              borderRadius: 8,
              fontSize: 12,
              color: "#e0e0e8",
            }}
            labelFormatter={(v) => `Call #${v}`}
            formatter={(value, _name, item) => {
              const v = Number(value ?? 0);
              const p = (item as unknown as { payload: { tool: string; delta: number } }).payload;
              return [
                `${v.toFixed(1)} (${p.delta >= 0 ? "+" : ""}${p.delta.toFixed(1)})`,
                p.tool,
              ];
            }}
          />
          <Area
            type="monotone"
            dataKey="risk"
            stroke="#00ff88"
            strokeWidth={2}
            fill="url(#riskGrad)"
            dot={false}
            activeDot={{ r: 4, fill: "#00ff88", stroke: "#0a0a0f", strokeWidth: 2 }}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
