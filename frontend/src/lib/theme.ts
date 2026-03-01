/** Shared color mappings and badge helpers for the monitor dashboard. */

export const ROLE_COLORS: Record<
  string,
  { bg: string; text: string; border: string }
> = {
  research: {
    bg: "bg-blue-500/15",
    text: "text-blue-400",
    border: "border-blue-500/30",
  },
  code: {
    bg: "bg-emerald-500/15",
    text: "text-emerald-400",
    border: "border-emerald-500/30",
  },
  financial: {
    bg: "bg-amber-500/15",
    text: "text-amber-400",
    border: "border-amber-500/30",
  },
  communication: {
    bg: "bg-purple-500/15",
    text: "text-purple-400",
    border: "border-purple-500/30",
  },
  admin: {
    bg: "bg-red-500/15",
    text: "text-red-400",
    border: "border-red-500/30",
  },
  data_analysis: {
    bg: "bg-cyan-500/15",
    text: "text-cyan-400",
    border: "border-cyan-500/30",
  },
};

export function verdictBadge(verdict: string) {
  switch (verdict) {
    case "allow":
      return { bg: "bg-emerald-500/15", text: "text-emerald-400", label: "ALLOW" };
    case "block":
      return { bg: "bg-red-500/15", text: "text-red-400", label: "BLOCK" };
    case "challenge":
      return { bg: "bg-amber-500/15", text: "text-amber-400", label: "CHALLENGE" };
    case "sandbox":
      return { bg: "bg-blue-500/15", text: "text-blue-400", label: "SANDBOX" };
    case "pause":
      return { bg: "bg-purple-500/15", text: "text-purple-400", label: "PAUSE" };
    default:
      return { bg: "bg-gray-500/15", text: "text-gray-400", label: verdict.toUpperCase() };
  }
}

export function riskColor(score: number): string {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-amber-400";
  return "text-emerald-400";
}

export function riskBgColor(score: number): string {
  if (score >= 80) return "bg-red-500/15";
  if (score >= 60) return "bg-orange-500/15";
  if (score >= 40) return "bg-amber-500/15";
  return "bg-emerald-500/15";
}

export const TAINT_COLORS: Record<string, { bg: string; text: string }> = {
  pii: { bg: "bg-red-500/15", text: "text-red-400" },
  credentials: { bg: "bg-orange-500/15", text: "text-orange-400" },
  financial: { bg: "bg-amber-500/15", text: "text-amber-400" },
  internal: { bg: "bg-blue-500/15", text: "text-blue-400" },
  source_code: { bg: "bg-purple-500/15", text: "text-purple-400" },
};
