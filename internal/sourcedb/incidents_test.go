package sourcedb

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/scalytics/kafSIEM/internal/collector/model"
)

func TestSaveAndLoadOSINTIncidents(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	incidents := []model.IncidentSummary{
		{
			IncidentID:     "inc-abc",
			Title:          "CVE wave",
			Category:       "cyber_advisory",
			Severity:       "high",
			MemberCount:    2,
			PrimaryAlertID: "a1",
			AlertIDs:       []string{"a1", "a2"},
			LinkReasons:    []string{"shared_cve:CVE-2026-1234"},
			CVEs:           []string{"CVE-2026-1234"},
			FirstSeen:      "2026-04-10T10:00:00Z",
			LastSeen:       "2026-04-10T12:00:00Z",
		},
	}
	if err := db.SaveOSINTIncidents(context.Background(), incidents); err != nil {
		t.Fatal(err)
	}

	list, err := db.ListOSINTIncidents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].IncidentID != "inc-abc" {
		t.Fatalf("unexpected list: %#v", list)
	}

	detail, ok, err := db.GetOSINTIncident(context.Background(), "inc-abc")
	if err != nil || !ok {
		t.Fatalf("get incident: ok=%v err=%v", ok, err)
	}
	if detail.MemberCount != 2 || len(detail.CVEs) != 1 {
		t.Fatalf("unexpected detail: %#v", detail)
	}
}

func TestGetOSINTIncidentRegressionResolvesMemberAlerts(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	alerts := []model.Alert{
		{
			AlertID:      "a1",
			SourceID:     "cert-a",
			Status:       "active",
			Title:        "Primary CVE advisory",
			CanonicalURL: "https://example.test/a1",
			Category:     "cyber_advisory",
			Severity:     "high",
			RegionTag:    "NA",
			FirstSeen:    "2026-04-10T10:00:00Z",
			LastSeen:     "2026-04-10T10:00:00Z",
			Source: model.SourceMetadata{
				SourceID:      "cert-a",
				AuthorityName: "CERT-A",
				Country:       "United States",
				CountryCode:   "US",
				Region:        "North America",
			},
		},
		{
			AlertID:      "a2",
			SourceID:     "cert-b",
			Status:       "active",
			Title:        "Corroborating CVE advisory",
			CanonicalURL: "https://example.test/a2",
			Category:     "cyber_advisory",
			Severity:     "high",
			RegionTag:    "EU",
			FirstSeen:    "2026-04-10T11:00:00Z",
			LastSeen:     "2026-04-10T11:00:00Z",
			Source: model.SourceMetadata{
				SourceID:      "cert-b",
				AuthorityName: "CERT-B",
				Country:       "Germany",
				CountryCode:   "DE",
				Region:        "Europe",
			},
		},
	}
	if err := db.SaveAlerts(context.Background(), alerts); err != nil {
		t.Fatal(err)
	}
	if err := db.SaveOSINTIncidents(context.Background(), []model.IncidentSummary{
		{
			IncidentID:     "inc-reg",
			Title:          "Primary CVE advisory",
			Category:       "cyber_advisory",
			Severity:       "high",
			MemberCount:    2,
			PrimaryAlertID: "a1",
			AlertIDs:       []string{"a1", "a2"},
			LinkReasons:    []string{"shared_cve:CVE-2026-1234"},
			CVEs:           []string{"CVE-2026-1234"},
			FirstSeen:      "2026-04-10T10:00:00Z",
			LastSeen:       "2026-04-10T11:00:00Z",
		},
	}); err != nil {
		t.Fatal(err)
	}

	detail, ok, err := db.GetOSINTIncident(context.Background(), "inc-reg")
	if err != nil || !ok {
		t.Fatalf("get incident: ok=%v err=%v", ok, err)
	}
	if len(detail.Alerts) != 2 {
		t.Fatalf("expected 2 resolved member alerts, got %d", len(detail.Alerts))
	}
}