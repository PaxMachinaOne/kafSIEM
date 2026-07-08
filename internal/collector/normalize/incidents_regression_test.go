package normalize

import (
	"testing"

	"github.com/scalytics/kafSIEM/internal/collector/model"
)

func TestApplyIncidentLinksRegressionSingletons(t *testing.T) {
	alerts := []model.Alert{
		{
			AlertID:   "solo-1",
			SourceID:  "src-a",
			Title:     "Unrelated public safety bulletin for region north",
			Category:  "public_safety",
			Severity:  "medium",
			FirstSeen: "2026-04-10T10:00:00Z",
			LastSeen:  "2026-04-10T10:00:00Z",
		},
	}
	linked, summaries := ApplyIncidentLinks(alerts)
	if len(summaries) != 0 {
		t.Fatalf("expected no incidents, got %#v", summaries)
	}
	if linked[0].Incident != nil {
		t.Fatal("singleton alert must not carry incident metadata")
	}
}

func TestApplyIncidentLinksRegressionSameSourceCVE(t *testing.T) {
	alerts := []model.Alert{
		{
			AlertID:   "c1",
			SourceID:  "cert-a",
			Title:     "Vendor bulletin for CVE-2026-5678 in controllers",
			Category:  "cyber_advisory",
			Severity:  "high",
			FirstSeen: "2026-04-10T10:00:00Z",
			LastSeen:  "2026-04-10T10:00:00Z",
			Triage:    &model.Triage{RelevanceScore: 0.4},
		},
		{
			AlertID:   "c2",
			SourceID:  "cert-a",
			Title:     "Updated guidance for CVE-2026-5678 exploitation attempts",
			Category:  "cyber_advisory",
			Severity:  "critical",
			FirstSeen: "2026-04-10T11:00:00Z",
			LastSeen:  "2026-04-10T11:00:00Z",
			Triage:    &model.Triage{RelevanceScore: 0.9},
		},
	}
	_, summaries := ApplyIncidentLinks(alerts)
	if len(summaries) != 1 {
		t.Fatalf("expected CVE incident across same source, got %d", len(summaries))
	}
	if summaries[0].PrimaryAlertID != "c2" {
		t.Fatalf("expected higher triage score as primary, got %s", summaries[0].PrimaryAlertID)
	}
}

func TestApplyIncidentLinksRegressionDeterministicID(t *testing.T) {
	alerts := []model.Alert{
		{
			AlertID:   "a1",
			SourceID:  "src-a",
			Title:     "Patch now for CVE-2026-4242 in VPN appliances",
			Category:  "cyber_advisory",
			Severity:  "high",
			FirstSeen: "2026-04-10T10:00:00Z",
			LastSeen:  "2026-04-10T10:00:00Z",
		},
		{
			AlertID:   "a2",
			SourceID:  "src-b",
			Title:     "Emergency advisory CVE-2026-4242 under active exploitation",
			Category:  "cyber_advisory",
			Severity:  "critical",
			FirstSeen: "2026-04-10T10:30:00Z",
			LastSeen:  "2026-04-10T10:30:00Z",
		},
	}
	_, first := ApplyIncidentLinks(alerts)
	_, second := ApplyIncidentLinks(alerts)
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("expected one incident, got %d and %d", len(first), len(second))
	}
	if first[0].IncidentID != second[0].IncidentID {
		t.Fatalf("incident id not stable: %s vs %s", first[0].IncidentID, second[0].IncidentID)
	}
}

func TestApplyIncidentLinksRegressionAllMembersAnnotated(t *testing.T) {
	alerts := []model.Alert{
		{
			AlertID:   "low",
			SourceID:  "src-a",
			Title:     "Mogadishu convoy ambush kills four security personnel",
			Category:  "conflict_monitoring",
			Severity:  "medium",
			FirstSeen: "2026-04-10T10:00:00Z",
			LastSeen:  "2026-04-10T10:00:00Z",
			Triage:    &model.Triage{RelevanceScore: 0.3},
		},
		{
			AlertID:   "high",
			SourceID:  "src-b",
			Title:     "Mogadishu convoy ambush leaves four security personnel dead",
			Category:  "conflict_monitoring",
			Severity:  "high",
			FirstSeen: "2026-04-10T10:15:00Z",
			LastSeen:  "2026-04-10T10:15:00Z",
			Triage:    &model.Triage{RelevanceScore: 0.8},
		},
	}
	linked, summaries := ApplyIncidentLinks(alerts)
	if len(summaries) != 1 {
		t.Fatalf("expected one incident, got %d", len(summaries))
	}
	annotated := 0
	for _, alert := range linked {
		if alert.Incident == nil {
			continue
		}
		annotated++
		if alert.Incident.MemberCount != 2 {
			t.Fatalf("expected member_count=2 on %s, got %d", alert.AlertID, alert.Incident.MemberCount)
		}
		if alert.AlertID == summaries[0].PrimaryAlertID {
			if alert.Incident.Role != "primary" {
				t.Fatalf("expected primary role on %s, got %s", alert.AlertID, alert.Incident.Role)
			}
			continue
		}
		if alert.Incident.Role != "member" {
			t.Fatalf("expected member role on %s, got %s", alert.AlertID, alert.Incident.Role)
		}
	}
	if annotated != 2 {
		t.Fatalf("expected both cluster members annotated, got %d", annotated)
	}
}