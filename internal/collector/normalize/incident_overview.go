// Copyright 2024 ff, Scalytics, Inc. - https://www.scalytics.io
// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"sort"
	"strings"

	"github.com/scalytics/kafSIEM/internal/collector/model"
)

// BuildIncidentOverview materializes timeline, geo, and relation-graph views
// from a persisted incident summary and hydrated member alerts.
func BuildIncidentOverview(summary model.IncidentSummary, alerts []model.Alert) (model.IncidentGeoSummary, []model.IncidentTimelineEntry, model.IncidentGraph) {
	byID := make(map[string]model.Alert, len(alerts))
	for _, alert := range alerts {
		byID[alert.AlertID] = alert
	}

	geo := model.IncidentGeoSummary{CountryCodes: uniqueSorted(append([]string{}, summary.Countries...))}
	countryNames := make(map[string]string)
	for _, alert := range alerts {
		code := strings.ToUpper(strings.TrimSpace(alert.EventCountryCode))
		if code == "" {
			code = strings.ToUpper(strings.TrimSpace(alert.Source.CountryCode))
		}
		if code == "" {
			continue
		}
		geo.CountryCodes = appendUniqueString(geo.CountryCodes, code)
		if name := strings.TrimSpace(alert.EventCountry); name != "" {
			countryNames[code] = name
		} else if name := strings.TrimSpace(alert.Source.Country); name != "" {
			countryNames[code] = name
		}
	}
	geo.CountryCodes = uniqueSorted(geo.CountryCodes)
	for _, code := range geo.CountryCodes {
		if name := countryNames[code]; name != "" {
			geo.Countries = append(geo.Countries, name)
		}
	}

	timeline := make([]model.IncidentTimelineEntry, 0, len(summary.AlertIDs))
	for _, alertID := range summary.AlertIDs {
		alert, ok := byID[alertID]
		if !ok {
			continue
		}
		role := "member"
		if alertID == summary.PrimaryAlertID {
			role = "primary"
		} else if alert.Incident != nil && alert.Incident.Role != "" {
			role = alert.Incident.Role
		}
		code := strings.ToUpper(strings.TrimSpace(alert.EventCountryCode))
		if code == "" {
			code = strings.ToUpper(strings.TrimSpace(alert.Source.CountryCode))
		}
		timeline = append(timeline, model.IncidentTimelineEntry{
			AlertID:       alert.AlertID,
			FirstSeen:     alert.FirstSeen,
			LastSeen:      alert.LastSeen,
			SourceID:      alert.SourceID,
			AuthorityName: alert.Source.AuthorityName,
			Title:         alert.Title,
			Severity:      alert.Severity,
			Category:      alert.Category,
			CountryCode:   code,
			Role:          role,
		})
	}
	sort.Slice(timeline, func(i, j int) bool {
		if timeline[i].FirstSeen == timeline[j].FirstSeen {
			return timeline[i].AlertID < timeline[j].AlertID
		}
		return timeline[i].FirstSeen < timeline[j].FirstSeen
	})

	nodes := make([]model.IncidentGraphNode, 0, len(timeline))
	for _, entry := range timeline {
		alert := byID[entry.AlertID]
		label := alert.Source.AuthorityName
		if len(label) > 48 {
			label = label[:45] + "..."
		}
		nodes = append(nodes, model.IncidentGraphNode{
			ID:          entry.AlertID,
			Kind:        "alert",
			Label:       label,
			SourceID:    entry.SourceID,
			CountryCode: entry.CountryCode,
			Severity:    entry.Severity,
			Role:        entry.Role,
			Lat:         alert.Lat,
			Lng:         alert.Lng,
		})
	}

	edges := make([]model.IncidentGraphEdge, 0)
	primaryID := strings.TrimSpace(summary.PrimaryAlertID)
	reasons := summary.LinkReasons
	if len(reasons) == 0 {
		reasons = []string{"incident:cluster"}
	}
	primaryReason := reasons[0]
	for _, entry := range timeline {
		if entry.AlertID == primaryID {
			continue
		}
		edges = append(edges, model.IncidentGraphEdge{
			From:   entry.AlertID,
			To:     primaryID,
			Reason: primaryReason,
		})
	}

	return geo, timeline, model.IncidentGraph{Nodes: nodes, Edges: uniqueIncidentEdges(edges)}
}

func uniqueIncidentEdges(edges []model.IncidentGraphEdge) []model.IncidentGraphEdge {
	seen := make(map[string]struct{}, len(edges))
	out := make([]model.IncidentGraphEdge, 0, len(edges))
	for _, edge := range edges {
		key := edge.From + "|" + edge.To + "|" + edge.Reason
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, edge)
	}
	return out
}

