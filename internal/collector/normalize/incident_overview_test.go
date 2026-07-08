package normalize

import (
	"testing"

	"github.com/scalytics/kafSIEM/internal/collector/model"
)

func TestBuildIncidentOverview(t *testing.T) {
	summary := model.IncidentSummary{
		IncidentID:     "inc-test",
		Title:          "Primary title",
		PrimaryAlertID: "a1",
		AlertIDs:       []string{"a1", "a2"},
		LinkReasons:    []string{"shared_cve:CVE-2026-1234"},
		Countries:      []string{"SO"},
		Entities:       []string{"Regional Cell"},
		CVEs:           []string{"CVE-2026-1234"},
	}
	alerts := []model.Alert{
		{
			AlertID: "a1",
			Title:   "Primary title",
			Source: model.SourceMetadata{
				AuthorityName: "Source A",
				CountryCode:   "SO",
				Country:       "Somalia",
			},
			FirstSeen:          "2026-04-10T10:00:00Z",
			Category:           "conflict_monitoring",
			Severity:           "high",
			EventCountryCode:   "SO",
			EventCountry:       "Somalia",
			Incident:           &model.IncidentLink{Role: "primary"},
		},
		{
			AlertID: "a2",
			Title:   "Corroborating title",
			Source: model.SourceMetadata{
				AuthorityName: "Source B",
				CountryCode:   "SO",
				Country:       "Somalia",
			},
			FirstSeen:        "2026-04-10T11:00:00Z",
			Category:         "conflict_monitoring",
			Severity:         "medium",
			EventCountryCode: "SO",
			Incident:         &model.IncidentLink{Role: "member"},
		},
	}

	geo, timeline, graph := BuildIncidentOverview(summary, alerts)
	if len(geo.CountryCodes) != 1 || geo.CountryCodes[0] != "SO" {
		t.Fatalf("unexpected geo: %#v", geo)
	}
	if len(timeline) != 2 || timeline[0].AlertID != "a1" {
		t.Fatalf("unexpected timeline: %#v", timeline)
	}
	if len(graph.Nodes) < 4 {
		t.Fatalf("expected alert + entity/country nodes, got %#v", graph.Nodes)
	}
	if len(graph.Edges) < 2 {
		t.Fatalf("expected corroboration and relation edges, got %#v", graph.Edges)
	}
}

func TestApplyIncidentLinksSharedCountry(t *testing.T) {
	alerts := []model.Alert{
		{
			AlertID:          "g1",
			SourceID:         "src-a",
			Title:            "Mogadishu airport security incident disrupts flights",
			Category:         "conflict_monitoring",
			Severity:         "high",
			EventCountryCode: "SO",
			FirstSeen:        "2026-04-10T10:00:00Z",
			LastSeen:         "2026-04-10T10:00:00Z",
		},
		{
			AlertID:          "g2",
			SourceID:         "src-b",
			Title:            "Mogadishu airport security incident causes flight delays",
			Category:         "conflict_monitoring",
			Severity:         "medium",
			EventCountryCode: "SO",
			FirstSeen:        "2026-04-10T11:00:00Z",
			LastSeen:         "2026-04-10T11:00:00Z",
		},
	}
	_, summaries := ApplyIncidentLinks(alerts)
	if len(summaries) != 1 {
		t.Fatalf("expected shared-country incident, got %d", len(summaries))
	}
	found := false
	for _, reason := range summaries[0].LinkReasons {
		if reason == "shared_country:SO" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected shared_country:SO in %#v", summaries[0].LinkReasons)
	}
}