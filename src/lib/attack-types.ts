import type { IncidentSummary } from "@/types/incident";

export type AttackType =
  | "cyber"
  | "terror"
  | "maritime"
  | "conflict"
  | "travel"
  | "hybrid"
  | "general";

export const attackTypeOrder: AttackType[] = [
  "cyber",
  "terror",
  "maritime",
  "conflict",
  "travel",
  "hybrid",
  "general",
];

export const attackTypeLabels: Record<AttackType, string> = {
  cyber: "Cyber attack",
  terror: "Terror / extremist",
  maritime: "Maritime threat",
  conflict: "Conflict event",
  travel: "Travel / security",
  hybrid: "Hybrid campaign",
  general: "Multi-source event",
};

export const attackTypeBadge: Record<AttackType, string> = {
  cyber: "border-cyan-400/35 bg-cyan-400/12 text-cyan-200",
  terror: "border-rose-400/35 bg-rose-400/12 text-rose-200",
  maritime: "border-blue-400/35 bg-blue-400/12 text-blue-200",
  conflict: "border-orange-400/35 bg-orange-400/12 text-orange-200",
  travel: "border-amber-400/35 bg-amber-400/12 text-amber-200",
  hybrid: "border-violet-400/35 bg-violet-400/12 text-violet-200",
  general: "border-siem-border bg-white/5 text-siem-muted",
};

export function normalizeAttackType(value: string | undefined): AttackType {
  switch ((value || "general").toLowerCase()) {
    case "cyber":
    case "terror":
    case "maritime":
    case "conflict":
    case "travel":
    case "hybrid":
      return value as AttackType;
    default:
      return "general";
  }
}

export function groupIncidentsByAttackType(incidents: IncidentSummary[]): Record<AttackType, IncidentSummary[]> {
  const grouped = Object.fromEntries(attackTypeOrder.map((type) => [type, [] as IncidentSummary[]])) as Record<
    AttackType,
    IncidentSummary[]
  >;
  for (const incident of incidents) {
    const type = normalizeAttackType(incident.attack_type);
    grouped[type].push(incident);
  }
  return grouped;
}