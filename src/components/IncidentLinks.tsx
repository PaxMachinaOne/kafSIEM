import { useState } from "react";
import { GitBranch, ChevronDown } from "lucide-react";
import type { Alert } from "@/types/alert";
import { formatLinkReason, incidentSummaryLine, resolveIncidentPeers } from "@/lib/incident-links";
import { categoryLabels } from "@/lib/severity";

interface Props {
  alert: Alert;
  alerts: Alert[];
  onSelectAlert: (alertId: string) => void;
}

export function IncidentLinks({ alert, alerts, onSelectAlert }: Props) {
  const [open, setOpen] = useState(false);
  const link = alert.incident;
  if (!link || link.member_count < 2) {
    return null;
  }

  const peers = resolveIncidentPeers(alert, alerts);
  const reasons = link.link_reasons ?? [];

  return (
    <div className="rounded-lg border border-siem-border bg-white/5">
      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        className="flex w-full items-center justify-between gap-3 px-3 py-3 text-left"
      >
        <div className="min-w-0">
          <div className="flex items-center gap-2 text-2xs uppercase tracking-wider text-siem-muted">
            <GitBranch size={12} />
            Linked incident
          </div>
          <div className="mt-1 text-sm text-siem-text">{incidentSummaryLine(link)}</div>
          <div className="mt-1 font-mono text-xxs text-siem-muted truncate">{link.incident_id}</div>
        </div>
        <ChevronDown size={16} className={`shrink-0 text-siem-muted transition-transform ${open ? "rotate-180" : ""}`} />
      </button>

      {open ? (
        <div className="space-y-3 border-t border-siem-border px-3 py-3">
          {reasons.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {reasons.map((reason) => (
                <span key={reason} className="rounded-full border border-siem-border px-2 py-0.5 text-xxs text-siem-muted">
                  {formatLinkReason(reason)}
                </span>
              ))}
            </div>
          ) : null}

          {peers.length > 0 ? (
            <div className="space-y-2">
              <div className="text-2xs uppercase tracking-wider text-siem-muted">Corroborating alerts</div>
              {peers.map((peer) => (
                <button
                  key={peer.alert_id}
                  type="button"
                  onClick={() => onSelectAlert(peer.alert_id)}
                  className="block w-full rounded-lg border border-siem-border bg-black/20 px-3 py-2 text-left hover:border-siem-accent/40"
                >
                  <div className="text-xs font-medium text-siem-text line-clamp-2">{peer.title}</div>
                  <div className="mt-1 text-xxs text-siem-muted">
                    {peer.source.authority_name} · {categoryLabels[peer.category]}
                  </div>
                </button>
              ))}
            </div>
          ) : (
            <p className="text-xxs text-siem-muted">
              Related alerts are indexed on this incident but not currently in the active feed.
            </p>
          )}
        </div>
      ) : null}
    </div>
  );
}