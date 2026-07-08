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