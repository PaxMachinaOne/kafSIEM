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
  malware?: string[];
  sectors?: string[];
  countries?: string[];
  attack_type?: string;
  first_seen: string;
  last_seen: string;
}

export interface IncidentTimelineEntry {
  alert_id: string;
  first_seen: string;
  last_seen?: string;
  source_id: string;
  authority_name: string;
  title: string;
  severity: string;
  category: string;
  country_code?: string;
  role?: string;
}

export interface IncidentGraphNode {
  id: string;
  kind: string;
  label: string;
  source_id: string;
  country_code?: string;
  severity: string;
  role?: string;
  lat?: number;
  lng?: number;
}

export interface IncidentGraphEdge {
  from: string;
  to: string;
  reason: string;
}

export interface IncidentGraph {
  nodes: IncidentGraphNode[];
  edges: IncidentGraphEdge[];
}

export interface IncidentGeoSummary {
  country_codes: string[];
  countries?: string[];
}

export interface IncidentDetail extends IncidentSummary {
  alerts: Alert[];
  geo: IncidentGeoSummary;
  timeline: IncidentTimelineEntry[];
  graph: IncidentGraph;
}

export interface IncidentsListResponse {
  items: IncidentSummary[];
  count: number;
}