import { describe, expect, it } from "vitest";
import { formatLinkReason, incidentSummaryLine, isIncidentAnchor, resolveIncidentPeers } from "@/lib/incident-links";
import type { Alert } from "@/types/alert";

function alert(id: string, title: string): Alert {
  return {
    alert_id: id,
    source_id: "src",
    source: {
      source_id: "src",
      authority_name: "CERT",
      country: "United States",
      country_code: "US",
      region: "North America",
      authority_type: "cert",
      base_url: "https://example.test",
    },
    title,
    canonical_url: "https://example.test/" + id,
    first_seen: "2026-04-10T10:00:00Z",
    last_seen: "2026-04-10T10:00:00Z",
    status: "active",
    category: "cyber_advisory",
    severity: "high",
    region_tag: "NA",
    lat: 0,
    lng: 0,
    freshness_hours: 1,
    incident: {
      incident_id: "inc-abc",
      member_count: 2,
      primary_alert_id: "a1",
      related_alert_ids: ["a2"],
      link_reasons: ["shared_cve:CVE-2026-1234"],
      shared_cves: ["CVE-2026-1234"],
    },
  };
}

describe("incident-links", () => {
  it("resolves related alerts from the active feed", () => {
    const primary = alert("a1", "Primary");
    const related = alert("a2", "Related");
    const peers = resolveIncidentPeers(primary, [primary, related]);
    expect(peers).toHaveLength(1);
    expect(peers[0]?.alert_id).toBe("a2");
  });

  it("formats link reasons for display", () => {
    expect(formatLinkReason("shared_cve:CVE-2026-1234")).toContain("CVE-2026-1234");
    expect(formatLinkReason("shared_entity:Islamic State")).toContain("Islamic State");
    expect(formatLinkReason("anchor:kev:CVE-2026-1234")).toContain("CISA KEV");
    expect(formatLinkReason("anchor:conflict_data:SO")).toContain("Conflict dataset");
  });

  it("detects incident anchors", () => {
    expect(isIncidentAnchor(alert("a1", "Primary"))).toBe(true);
    expect(isIncidentAnchor({ ...alert("solo", "Solo"), incident: undefined })).toBe(false);
  });

  it("returns empty peers when related ids are absent from feed", () => {
    const primary = alert("a1", "Primary");
    expect(resolveIncidentPeers(primary, [primary])).toEqual([]);
  });

  it("builds a compact summary line", () => {
    const line = incidentSummaryLine({
      incident_id: "inc-abc",
      member_count: 3,
      shared_cves: ["CVE-2026-1234"],
    });
    expect(line).toContain("3 linked alerts");
    expect(line).toContain("CVE-2026-1234");
  });
});