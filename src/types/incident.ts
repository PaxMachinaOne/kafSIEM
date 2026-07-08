import type { Alert } from "@/types/alert";

export interface IncidentSummary {
  incident_id: string;
  title: string;
  category: string;
  severity: string;
  member_count: number;
  primary_alert_id: string;
  alert_ids: string[];
  link_reasons?: string[];
  cves?: string[];
  entities?: string[];
  first_seen: string;
  last_seen: string;
}

export interface IncidentDetail extends IncidentSummary {
  alerts: Alert[];
}

export interface IncidentsListResponse {
  items: IncidentSummary[];
  count: number;
}