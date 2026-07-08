import { useMemo, useState } from "react";
import { GitBranch, ShieldAlert, Radar } from "lucide-react";
import { useIncidents } from "@/hooks/useIncidents";
import {
  attackTypeBadge,
  attackTypeLabels,
  attackTypeOrder,
  groupIncidentsByAttackType,
  normalizeAttackType,
  type AttackType,
} from "@/lib/attack-types";
import { formatLinkReason } from "@/lib/incident-links";
import type { IncidentSummary } from "@/types/incident";

interface Props {
  onSelectIncident: (incident: IncidentSummary) => void;
}

export function IncidentRelationsPanel({ onSelectIncident }: Props) {
  const { incidents, isLoading, isAvailable } = useIncidents(100);
  const [attackFilter, setAttackFilter] = useState<AttackType | "all">("all");

  const grouped = useMemo(() => groupIncidentsByAttackType(incidents), [incidents]);
  const visible = useMemo(() => {
    if (attackFilter === "all") return incidents;
    return grouped[attackFilter] ?? [];
  }, [attackFilter, grouped, incidents]);

  const attackCounts = useMemo(
    () =>
      attackTypeOrder
        .map((type) => ({ type, count: grouped[type]?.length ?? 0 }))
        .filter((entry) => entry.count > 0),
    [grouped],
  );

  return (
    <section className="flex h-full flex-col overflow-hidden rounded-[1.6rem] border border-siem-border bg-siem-panel/90 shadow-[0_24px_80px_rgba(0,0,0,0.28)]">
      <div className="border-b border-siem-border/80 px-4 py-3">
        <div className="flex items-center gap-2 text-4xs uppercase tracking-[0.2em] text-siem-muted">
          <GitBranch size={10} />
          Attack relations
        </div>
        <div className="mt-1 text-sm text-siem-text">Corroborated clusters across cyber, terror, maritime, and conflict feeds.</div>
      </div>

      <div className="border-b border-siem-border/80 px-3 py-2">
        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setAttackFilter("all")}
            className={`rounded-full border px-2 py-1 text-4xs uppercase tracking-[0.14em] ${
              attackFilter === "all" ? "border-siem-accent/45 bg-siem-accent/12 text-siem-text" : "border-siem-border text-siem-muted"
            }`}
          >
            All ({incidents.length})
          </button>
          {attackCounts.map(({ type, count }) => (
            <button
              key={type}
              type="button"
              onClick={() => setAttackFilter(type)}
              className={`rounded-full border px-2 py-1 text-4xs uppercase tracking-[0.14em] ${
                attackFilter === type ? attackTypeBadge[type] : "border-siem-border text-siem-muted"
              }`}
            >
              {attackTypeLabels[type]} ({count})
            </button>
          ))}
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-3 space-y-2">
        {isLoading ? (
          <div className="text-sm text-siem-muted">Loading relation clusters...</div>
        ) : visible.length === 0 ? (
          <div className="rounded-lg border border-siem-border bg-black/20 px-3 py-4 text-sm text-siem-muted">
            {isAvailable
              ? "No corroborated attack clusters in the current index. Clusters form when cyber, terror, or conflict alerts share CVEs, actors, or geography across sources."
              : "Incidents API unavailable. Run make dev-start or make demo-osint."}
          </div>
        ) : (
          visible.map((incident) => (
            <IncidentRelationCard key={incident.incident_id} incident={incident} onSelectIncident={onSelectIncident} />
          ))
        )}
      </div>
    </section>
  );
}

function IncidentRelationCard({
  incident,
  onSelectIncident,
}: {
  incident: IncidentSummary;
  onSelectIncident: (incident: IncidentSummary) => void;
}) {
  const attackType = normalizeAttackType(incident.attack_type);
  const reasons = (incident.link_reasons ?? []).slice(0, 3);

  return (
    <button
      type="button"
      onClick={() => onSelectIncident(incident)}
      className="w-full rounded-xl border border-siem-border bg-siem-panel-strong px-3 py-3 text-left transition-colors hover:border-siem-accent/35 hover:bg-siem-accent/8"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className={`rounded-full border px-2 py-0.5 text-4xs uppercase tracking-[0.14em] ${attackTypeBadge[attackType]}`}>
              {attackTypeLabels[attackType]}
            </span>
            <span className="rounded-full border border-siem-border px-2 py-0.5 text-4xs uppercase tracking-[0.14em] text-siem-muted">
              {incident.member_count} sources
            </span>
          </div>
          <div className="mt-2 text-sm font-medium text-siem-text line-clamp-2">{incident.title}</div>
          <div className="mt-1 font-mono text-xxs text-siem-muted truncate">{incident.incident_id}</div>
        </div>
        {attackType === "cyber" ? <ShieldAlert size={16} className="shrink-0 text-cyan-300" /> : <Radar size={16} className="shrink-0 text-orange-300" />}
      </div>

      {reasons.length > 0 ? (
        <div className="mt-2 flex flex-wrap gap-1">
          {reasons.map((reason) => (
            <span key={reason} className="rounded-full border border-siem-border px-2 py-0.5 text-xxs text-siem-muted">
              {formatLinkReason(reason)}
            </span>
          ))}
        </div>
      ) : null}
    </button>
  );
}
