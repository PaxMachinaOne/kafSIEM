// Copyright 2024 ff, Scalytics, Inc. - https://www.scalytics.io
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/scalytics/kafSIEM/internal/collector/model"
)

var cvePattern = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,}\b`)

const (
	cveIncidentWindowHours     = 14 * 24
	entityIncidentWindowHours  = 7 * 24
	countryIncidentWindowHours = 7 * 24
	countryWeakJaccardThreshold = 0.35
)

type incidentFingerprints struct {
	alert   model.Alert
	tokens  []string
	ts      time.Time
	cves    []string
	actors  []string
	country string
}

type alertUnion struct {
	parent map[string]string
}

func newAlertUnion() *alertUnion {
	return &alertUnion{parent: map[string]string{}}
}

func (u *alertUnion) find(id string) string {
	parent, ok := u.parent[id]
	if !ok {
		u.parent[id] = id
		return id
	}
	if parent == id {
		return id
	}
	root := u.find(parent)
	u.parent[id] = root
	return root
}

func (u *alertUnion) union(a, b string) {
	rootA := u.find(a)
	rootB := u.find(b)
	if rootA == rootB {
		return
	}
	if rootA < rootB {
		u.parent[rootB] = rootA
		return
	}
	u.parent[rootA] = rootB
}

// ApplyIncidentLinks annotates active alerts with incident clusters built from
// cross-source fingerprint similarity, shared CVE identifiers, shared actors,
// and shared event geography.
func ApplyIncidentLinks(alerts []model.Alert) ([]model.Alert, []model.IncidentSummary) {
	if len(alerts) == 0 {
		return alerts, nil
	}

	anchors := BuildRelationAnchors(alerts)
	dict := loadEntityDict()
	fps := make([]incidentFingerprints, 0, len(alerts))
	alertIndex := make(map[string]model.Alert, len(alerts))
	for _, alert := range alerts {
		alertIndex[alert.AlertID] = alert
		tokens := contentFingerprint(alert, dict)
		if len(tokens) < minFingerprintTokens {
			continue
		}
		fps = append(fps, incidentFingerprints{
			alert:   alert,
			tokens:  tokens,
			ts:      parseAlertTime(alert),
			cves:    extractCVEs(alert.Title),
			actors:  extractEntityNames(tokens),
			country: eventCountryCode(alert),
		})
	}

	union := newAlertUnion()
	reasonsByAlert := make(map[string][]string)
	cvesByAlert := make(map[string][]string)
	actorsByAlert := make(map[string][]string)

	for _, fp := range fps {
		for _, cve := range fp.cves {
			cvesByAlert[fp.alert.AlertID] = appendUniqueString(cvesByAlert[fp.alert.AlertID], cve)
		}
		for _, actor := range fp.actors {
			actorsByAlert[fp.alert.AlertID] = appendUniqueString(actorsByAlert[fp.alert.AlertID], actor)
		}
	}

	for i := range fps {
		for j := i + 1; j < len(fps); j++ {
			left := fps[i]
			right := fps[j]
			if hoursApart(left.ts, right.ts) > fingerprintTimeWindowHours {
				continue
			}
			if left.alert.SourceID != right.alert.SourceID &&
				jaccardSimilarity(left.tokens, right.tokens) >= fingerprintSimilarityThreshold {
				union.union(left.alert.AlertID, right.alert.AlertID)
				score := jaccardSimilarity(left.tokens, right.tokens)
				reason := "cross_source:jaccard:" + formatScore(score)
				reasonsByAlert[left.alert.AlertID] = appendUniqueString(reasonsByAlert[left.alert.AlertID], reason)
				reasonsByAlert[right.alert.AlertID] = appendUniqueString(reasonsByAlert[right.alert.AlertID], reason)
			}
		}
	}

	for i := range fps {
		for j := i + 1; j < len(fps); j++ {
			left := fps[i]
			right := fps[j]
			if hoursApart(left.ts, right.ts) > cveIncidentWindowHours {
				continue
			}
			shared := intersectStrings(left.cves, right.cves)
			if len(shared) == 0 {
				continue
			}
			union.union(left.alert.AlertID, right.alert.AlertID)
			for _, cve := range shared {
				reason := "shared_cve:" + cve
				reasonsByAlert[left.alert.AlertID] = appendUniqueString(reasonsByAlert[left.alert.AlertID], reason)
				reasonsByAlert[right.alert.AlertID] = appendUniqueString(reasonsByAlert[right.alert.AlertID], reason)
			}
		}
	}

	for i := range fps {
		for j := i + 1; j < len(fps); j++ {
			left := fps[i]
			right := fps[j]
			if !entityLinkCategory(left.alert.Category) || left.alert.Category != right.alert.Category {
				continue
			}
			if hoursApart(left.ts, right.ts) > entityIncidentWindowHours {
				continue
			}
			shared := intersectStrings(left.actors, right.actors)
			if len(shared) == 0 {
				continue
			}
			union.union(left.alert.AlertID, right.alert.AlertID)
			for _, actor := range shared {
				reason := "shared_entity:" + actor
				reasonsByAlert[left.alert.AlertID] = appendUniqueString(reasonsByAlert[left.alert.AlertID], reason)
				reasonsByAlert[right.alert.AlertID] = appendUniqueString(reasonsByAlert[right.alert.AlertID], reason)
			}
		}
	}

	for i := range fps {
		for j := i + 1; j < len(fps); j++ {
			left := fps[i]
			right := fps[j]
			if !shouldCountryLink(left, right) {
				continue
			}
			union.union(left.alert.AlertID, right.alert.AlertID)
			reason := "shared_country:" + strings.ToUpper(left.country)
			reasonsByAlert[left.alert.AlertID] = appendUniqueString(reasonsByAlert[left.alert.AlertID], reason)
			reasonsByAlert[right.alert.AlertID] = appendUniqueString(reasonsByAlert[right.alert.AlertID], reason)
		}
	}

	groups := make(map[string][]string)
	for _, fp := range fps {
		root := union.find(fp.alert.AlertID)
		groups[root] = appendUniqueString(groups[root], fp.alert.AlertID)
	}

	out := make([]model.Alert, len(alerts))
	copy(out, alerts)
	summaries := make([]model.IncidentSummary, 0)

	for root, memberIDs := range groups {
		memberIDs = uniqueSorted(memberIDs)
		if len(memberIDs) < 2 {
			continue
		}
		incidentID := incidentIDFromParts("bundle", root)
		primary := pickPrimaryAlert(memberIDs, alertIndex)
		reasons := uniqueSorted(collectReasons(memberIDs, reasonsByAlert))
		sharedCVEs := uniqueSorted(collectCVEs(memberIDs, cvesByAlert))
		sharedEntities := uniqueSorted(collectActors(memberIDs, actorsByAlert))
		memberAlerts := make([]model.Alert, 0, len(memberIDs))
		for _, id := range memberIDs {
			memberAlerts = append(memberAlerts, alertIndex[id])
		}
		sharedCountries := collectCountries(memberIDs, alertIndex)
		reasons = ApplyAnchorCorroboration(reasons, memberAlerts, sharedCVEs, sharedEntities, anchors)
		for _, id := range memberIDs {
			for i := range out {
				if out[i].AlertID != id {
					continue
				}
				out[i].Incident = buildIncidentLink(incidentID, primary.AlertID, id, memberIDs, reasons, sharedCVEs, sharedEntities, sharedCountries)
				break
			}
		}
		summaries = append(summaries, model.IncidentSummary{
			IncidentID:     incidentID,
			Title:          primary.Title,
			Category:       primary.Category,
			Severity:       primary.Severity,
			MemberCount:    len(memberIDs),
			PrimaryAlertID: primary.AlertID,
			AlertIDs:       memberIDs,
			LinkReasons:    reasons,
			CVEs:           sharedCVEs,
			Entities:       sharedEntities,
			Countries:      sharedCountries,
			FirstSeen:      earliestSeen(memberIDs, alertIndex),
			LastSeen:       latestSeen(memberIDs, alertIndex),
		})
	}

	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].LastSeen > summaries[j].LastSeen
	})
	return out, summaries
}

// FinalizeActiveAlerts builds incident clusters before cross-source dedup
// collapses corroborating alerts out of the active feed.
func FinalizeActiveAlerts(alerts []model.Alert) ([]model.Alert, []model.IncidentSummary, int) {
	linked, summaries := ApplyIncidentLinks(alerts)
	finalized, suppressed := crossSourceDedup(linked)
	return finalized, summaries, suppressed
}

func extractCVEs(text string) []string {
	matches := cvePattern.FindAllString(text, -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(matches))
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		normalized := strings.ToUpper(match)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out
}

func extractEntityNames(tokens []string) []string {
	out := make([]string, 0)
	for _, token := range tokens {
		if !strings.HasPrefix(token, "entity:") {
			continue
		}
		out = appendUniqueString(out, strings.TrimPrefix(token, "entity:"))
	}
	return out
}

func buildIncidentLink(
	incidentID string,
	primaryAlertID string,
	alertID string,
	memberIDs []string,
	reasons []string,
	sharedCVEs []string,
	sharedEntities []string,
	sharedCountries []string,
) *model.IncidentLink {
	related := make([]string, 0, len(memberIDs)-1)
	for _, id := range memberIDs {
		if id != alertID {
			related = append(related, id)
		}
	}
	role := "member"
	if alertID == primaryAlertID {
		role = "primary"
	}
	return &model.IncidentLink{
		IncidentID:      incidentID,
		MemberCount:     len(memberIDs),
		PrimaryAlertID:  primaryAlertID,
		Role:            role,
		RelatedAlertIDs: related,
		LinkReasons:     reasons,
		SharedCVEs:      sharedCVEs,
		SharedEntities:  sharedEntities,
		SharedCountries: sharedCountries,
	}
}

func eventCountryCode(alert model.Alert) string {
	return strings.ToUpper(strings.TrimSpace(alert.EventCountryCode))
}

func countryLinkCategory(category string) bool {
	switch category {
	case "terrorism_tip", "conflict_monitoring", "travel_warning", "humanitarian_security", "maritime_security", "public_safety":
		return true
	default:
		return false
	}
}

func shouldCountryLink(left, right incidentFingerprints) bool {
	if left.country == "" || left.country != right.country {
		return false
	}
	if left.alert.SourceID == right.alert.SourceID {
		return false
	}
	if !countryLinkCategory(left.alert.Category) || left.alert.Category != right.alert.Category {
		return false
	}
	if hoursApart(left.ts, right.ts) > countryIncidentWindowHours {
		return false
	}
	if jaccardSimilarity(left.tokens, right.tokens) >= countryWeakJaccardThreshold {
		return true
	}
	if len(intersectStrings(left.actors, right.actors)) > 0 {
		return true
	}
	if len(intersectStrings(left.cves, right.cves)) > 0 {
		return true
	}
	return false
}

func collectCountries(memberIDs []string, alertIndex map[string]model.Alert) []string {
	out := make([]string, 0)
	for _, id := range memberIDs {
		alert := alertIndex[id]
		if code := eventCountryCode(alert); code != "" {
			out = append(out, code)
			continue
		}
		if code := strings.ToUpper(strings.TrimSpace(alert.Source.CountryCode)); code != "" {
			out = append(out, code)
		}
	}
	return uniqueSorted(out)
}

func entityLinkCategory(category string) bool {
	switch category {
	case "terrorism_tip", "conflict_monitoring", "cyber_advisory", "maritime_security":
		return true
	default:
		return false
	}
}

func incidentIDFromParts(kind, key string) string {
	payload := kind + ":" + strings.TrimSpace(strings.ToLower(key))
	sum := sha256.Sum256([]byte(payload))
	return "inc-" + hex.EncodeToString(sum[:6])
}

func hoursApart(a, b time.Time) float64 {
	delta := a.Sub(b).Hours()
	if delta < 0 {
		return -delta
	}
	return delta
}

func formatScore(score float64) string {
	return fmt.Sprintf("%.2f", score)
}

func appendUniqueString(values []string, next string) []string {
	next = strings.TrimSpace(next)
	if next == "" {
		return values
	}
	for _, value := range values {
		if value == next {
			return values
		}
	}
	return append(values, next)
}

func intersectStrings(left, right []string) []string {
	if len(left) == 0 || len(right) == 0 {
		return nil
	}
	set := make(map[string]bool, len(left))
	for _, item := range left {
		set[item] = true
	}
	out := make([]string, 0)
	for _, item := range right {
		if set[item] {
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}

func uniqueSorted(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	set := make(map[string]bool, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			set[value] = true
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func collectReasons(memberIDs []string, reasonsByAlert map[string][]string) []string {
	out := make([]string, 0)
	for _, id := range memberIDs {
		out = append(out, reasonsByAlert[id]...)
	}
	return out
}

func collectCVEs(memberIDs []string, cvesByAlert map[string][]string) []string {
	out := make([]string, 0)
	for _, id := range memberIDs {
		out = append(out, cvesByAlert[id]...)
	}
	return uniqueSorted(out)
}

func collectActors(memberIDs []string, actorsByAlert map[string][]string) []string {
	out := make([]string, 0)
	for _, id := range memberIDs {
		out = append(out, actorsByAlert[id]...)
	}
	return uniqueSorted(out)
}

func pickPrimaryAlert(memberIDs []string, alertIndex map[string]model.Alert) model.Alert {
	best := alertIndex[memberIDs[0]]
	bestScore := alertScore(best)
	for _, id := range memberIDs[1:] {
		candidate := alertIndex[id]
		score := alertScore(candidate)
		if score > bestScore {
			best = candidate
			bestScore = score
			continue
		}
		if score == bestScore && candidate.FirstSeen < best.FirstSeen {
			best = candidate
		}
	}
	return best
}

func earliestSeen(memberIDs []string, alertIndex map[string]model.Alert) string {
	earliest := ""
	for _, id := range memberIDs {
		seen := alertIndex[id].FirstSeen
		if earliest == "" || seen < earliest {
			earliest = seen
		}
	}
	return earliest
}

func latestSeen(memberIDs []string, alertIndex map[string]model.Alert) string {
	latest := ""
	for _, id := range memberIDs {
		seen := alertIndex[id].LastSeen
		if seen > latest {
			latest = seen
		}
	}
	return latest
}