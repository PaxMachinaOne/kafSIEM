import type { Alert, IncidentLink } from "@/types/alert";

export function isIncidentMember(alert: Alert): boolean {
  return (alert.incident?.member_count ?? 0) >= 2;
}

export function isIncidentAnchor(alert: Alert): boolean {
  return isIncidentMember(alert);
}

export function isIncidentPrimary(alert: Alert): boolean {
  const link = alert.incident;
  if (!link) return false;
  return link.role === "primary" || alert.alert_id === link.primary_alert_id;
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

export function mergeIncidentPeers(
  alert: Alert,
  localAlerts: Alert[],
  remoteAlerts: Alert[] | undefined,
): Alert[] {
  const local = resolveIncidentPeers(alert, localAlerts);
  const remote = (remoteAlerts ?? []).filter((item) => item.alert_id !== alert.alert_id);
  const byID = new Map<string, Alert>();
  for (const peer of [...local, ...remote]) {
    byID.set(peer.alert_id, peer);
  }
  return [...byID.values()];
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
  if (reason.startsWith("anchor:epss:")) {
    return `High EPSS score (${reason.slice("anchor:epss:".length)})`;
  }
  if (reason.startsWith("anchor:sanctioned:")) {
    return `Sanctions listing (${reason.slice("anchor:sanctioned:".length)})`;
  }
  if (reason.startsWith("shared_country:")) {
    return `Shared geography (${reason.slice("shared_country:".length)})`;
  }
  return reason.replaceAll("_", " ");
}

export function incidentSummaryLine(link: IncidentLink): string {
  const parts: string[] = [`${link.member_count} linked alerts`];
  if (link.shared_cves?.length) {
    parts.push(link.shared_cves.join(", "));
  } else if (link.shared_entities?.length) {
    parts.push(link.shared_entities.join(", "));
  } else if (link.shared_countries?.length) {
    parts.push(link.shared_countries.join(", "));
  }
  return parts.join(" · ");
}