package normalize

import (
	"testing"

	"github.com/scalytics/kafSIEM/internal/collector/model"
)

func TestClassifyAttackTypeCyber(t *testing.T) {
	summary := model.IncidentSummary{
		CVEs:        []string{"CVE-2026-1234"},
		LinkReasons: []string{"shared_cve:CVE-2026-1234"},
		Category:    "cyber_advisory",
	}
	if got := ClassifyAttackType(summary, nil); got != "cyber" {
		t.Fatalf("expected cyber, got %s", got)
	}
}

func TestClassifyAttackTypeTerrorCrossCategory(t *testing.T) {
	summary := model.IncidentSummary{
		Entities:    []string{"Al-Shabaab"},
		LinkReasons: []string{"cross_category_entity:Al-Shabaab"},
		Category:    "conflict_monitoring",
	}
	alerts := []model.Alert{
		{Category: "conflict_monitoring"},
		{Category: "terrorism_tip"},
	}
	if got := ClassifyAttackType(summary, alerts); got != "terror" {
		t.Fatalf("expected terror, got %s", got)
	}
}

func TestShouldEntityLinkCrossCategoryKnownActor(t *testing.T) {
	left := incidentFingerprints{
		alert:  model.Alert{AlertID: "a1", SourceID: "src-a", Category: "conflict_monitoring"},
		actors: []string{"Al-Shabaab"},
	}
	right := incidentFingerprints{
		alert:  model.Alert{AlertID: "a2", SourceID: "src-b", Category: "terrorism_tip"},
		actors: []string{"Al-Shabaab"},
	}
	if !shouldEntityLink(left, right, []string{"Al-Shabaab"}) {
		t.Fatal("expected cross-category entity link for known actor")
	}
}