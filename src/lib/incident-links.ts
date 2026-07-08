import type { Alert, IncidentLink } from "@/types/alert";

export function isIncidentAnchor(alert: Alert): boolean {
  return (alert.incident?.member_count ?? 0) >= 2;
}

export function resolveIncidentPeers(alert: Alert, alerts: Alert[]): Alert[] {
  const link = alert.incident;
  if (!link?.related_alert_ids?.length) {
    return [];
  }
  const byID = new Map(alerts.map((item) => [item.alert_id, item]));
  return link.related_alert_ids
    .map((id) => byID.get(id))
    .filter((item): item is Alert => Boolean(item));
}

export function formatLinkReason(reason: string): string {
  if (reason.startsWith("shared_cve:")) {
    return `Shared ${reason.slice("shared_cve:".length)}`;
  }
  if (reason.startsWith("shared_entity:")) {
    return `Shared actor: ${reason.slice("shared_entity:".length)}`;
  }
  if (reason.startsWith("cross_source:jaccard:")) {
    return `Cross-source match (${reason.slice("cross_source:jaccard:".length)})`;
  }
  if (reason.startsWith("anchor:kev:")) {
    return `CISA KEV confirmed (${reason.slice("anchor:kev:".length)})`;
  }
  if (reason.startsWith("anchor:known_actor:")) {
    return `Known actor registry (${reason.slice("anchor:known_actor:".length)})`;
  }
  if (reason.startsWith("anchor:travel_warning:")) {
    return `Travel warning active (${reason.slice("anchor:travel_warning:".length)})`;
  }
  if (reason.startsWith("anchor:conflict_data:")) {
    return `Conflict dataset corroboration (${reason.slice("anchor:conflict_data:".length)})`;
  }
  return reason.replaceAll("_", " ");
}

export function incidentSummaryLine(link: IncidentLink): string {
  const parts: string[] = [`${link.member_count} linked alerts`];
  if (link.shared_cves?.length) {
    parts.push(link.shared_cves.join(", "));
  } else if (link.shared_entities?.length) {
    parts.push(link.shared_entities.join(", "));
  }
  return parts.join(" · ");
}