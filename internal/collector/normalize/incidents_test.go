package normalize

import (
	"testing"

	"github.com/scalytics/kafSIEM/internal/collector/model"
)

func TestApplyIncidentLinksCrossSource(t *testing.T) {
	alerts := []model.Alert{
		{
			AlertID:  "a1",
			SourceID: "src-a",
			Title:    "Mogadishu market attack kills twelve civilians",
			Category: "terrorism_tip",
			Severity: "high",
			FirstSeen: "2026-04-10T10:00:00Z",
			LastSeen:  "2026-04-10T10:00:00Z",
		},
		{
			AlertID:  "a2",
			SourceID: "src-b",
			Title:    "Mogadishu market attack leaves twelve civilians dead",
			Category: "terrorism_tip",
			Severity: "high",
			FirstSeen: "2026-04-10T11:00:00Z",
			LastSeen:  "2026-04-10T11:00:00Z",
		},
	}

	linked, summaries := ApplyIncidentLinks(alerts)
	if len(summaries) != 1 {
		t.Fatalf("expected 1 incident summary, got %d", len(summaries))
	}
	if summaries[0].MemberCount != 2 {
		t.Fatalf("expected 2 members, got %d", summaries[0].MemberCount)
	}

	var withLink *model.Alert
	for i := range linked {
		if linked[i].Incident != nil {
			withLink = &linked[i]
			break
		}
	}
	if withLink == nil {
		t.Fatal("expected primary alert to carry incident link")
	}
	if len(withLink.Incident.RelatedAlertIDs) != 1 {
		t.Fatalf("expected 1 related alert, got %v", withLink.Incident.RelatedAlertIDs)
	}
}

func TestApplyIncidentLinksCVE(t *testing.T) {
	alerts := []model.Alert{
		{
			AlertID:  "c1",
			SourceID: "cert-a",
			Title:    "CISA adds CVE-2026-1234 to KEV catalog",
			Category: "cyber_advisory",
			Severity: "critical",
			FirstSeen: "2026-04-10T10:00:00Z",
			LastSeen:  "2026-04-10T10:00:00Z",
		},
		{
			AlertID:  "c2",
			SourceID: "cert-b",
			Title:    "Patch advisory for CVE-2026-1234 in edge routers",
			Category: "cyber_advisory",
			Severity: "high",
			FirstSeen: "2026-04-10T12:00:00Z",
			LastSeen:  "2026-04-10T12:00:00Z",
		},
	}

	_, summaries := ApplyIncidentLinks(alerts)
	if len(summaries) != 1 {
		t.Fatalf("expected 1 CVE incident, got %d", len(summaries))
	}
	if len(summaries[0].CVEs) == 0 || summaries[0].CVEs[0] != "CVE-2026-1234" {
		t.Fatalf("expected CVE-2026-1234 in summary, got %v", summaries[0].CVEs)
	}
}

func TestExtractCVEs(t *testing.T) {
	got := extractCVEs("Critical CVE-2026-9999 and cve-2026-1111 advisories")
	if len(got) != 2 || got[0] != "CVE-2026-1111" || got[1] != "CVE-2026-9999" {
		t.Fatalf("unexpected CVE extraction: %v", got)
	}
}