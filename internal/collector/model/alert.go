// Copyright 2024 ff, Scalytics, Inc. - https://www.scalytics.io
// SPDX-License-Identifier: Apache-2.0

package model

type Alert struct {
	AlertID            string            `json:"alert_id"`
	SourceID           string            `json:"source_id"`
	Source             SourceMetadata    `json:"source"`
	Title              string            `json:"title"`
	CanonicalURL       string            `json:"canonical_url"`
	FirstSeen          string            `json:"first_seen"`
	LastSeen           string            `json:"last_seen"`
	Status             string            `json:"status"`
	Category           string            `json:"category"`
	Subcategory        string            `json:"subcategory,omitempty"`
	Severity           string            `json:"severity"`
	SignalLane         SignalLane        `json:"signal_lane,omitempty"`
	RegionTag          string            `json:"region_tag"`
	Lat                float64           `json:"lat"`
	Lng                float64           `json:"lng"`
	EventCountry       string            `json:"event_country,omitempty"`
	EventCountryCode   string            `json:"event_country_code,omitempty"`
	EventGeoSource     string            `json:"event_geo_source,omitempty"`
	EventGeoConfidence float64           `json:"event_geo_confidence,omitempty"`
	FreshnessHours     int               `json:"freshness_hours"`
	Reporting          ReportingMetadata `json:"reporting,omitempty"`
	Triage             *Triage           `json:"triage,omitempty"`
	Incident           *IncidentLink     `json:"incident,omitempty"`
}

// IncidentLink connects an alert to a corroborated OSINT incident cluster.
type IncidentLink struct {
	IncidentID        string   `json:"incident_id"`
	MemberCount       int      `json:"member_count"`
	PrimaryAlertID    string   `json:"primary_alert_id,omitempty"`
	Role              string   `json:"role,omitempty"`
	RelatedAlertIDs   []string `json:"related_alert_ids,omitempty"`
	LinkReasons       []string `json:"link_reasons,omitempty"`
	SharedCVEs        []string `json:"shared_cves,omitempty"`
	SharedEntities    []string `json:"shared_entities,omitempty"`
	SharedCountries   []string `json:"shared_countries,omitempty"`
}

// IncidentSummary is the index record written to incidents.json.
type IncidentSummary struct {
	IncidentID     string   `json:"incident_id"`
	Title          string   `json:"title"`
	Category       string   `json:"category"`
	Severity       string   `json:"severity"`
	MemberCount    int      `json:"member_count"`
	PrimaryAlertID string   `json:"primary_alert_id"`
	AlertIDs       []string `json:"alert_ids"`
	LinkReasons    []string `json:"link_reasons"`
	CVEs           []string `json:"cves,omitempty"`
	Entities       []string `json:"entities,omitempty"`
	Countries      []string `json:"countries,omitempty"`
	AttackType     string   `json:"attack_type,omitempty"`
	FirstSeen      string   `json:"first_seen"`
	LastSeen       string   `json:"last_seen"`
}

// IncidentTimelineEntry is a chronological member alert in an incident overview.
type IncidentTimelineEntry struct {
	AlertID       string `json:"alert_id"`
	FirstSeen     string `json:"first_seen"`
	LastSeen      string `json:"last_seen,omitempty"`
	SourceID      string `json:"source_id"`
	AuthorityName string `json:"authority_name"`
	Title         string `json:"title"`
	Severity      string `json:"severity"`
	Category      string `json:"category"`
	CountryCode   string `json:"country_code,omitempty"`
	Role          string `json:"role,omitempty"`
}

// IncidentGraphNode is an alert node in the incident relation graph.
type IncidentGraphNode struct {
	ID          string  `json:"id"`
	Kind        string  `json:"kind"`
	Label       string  `json:"label"`
	SourceID    string  `json:"source_id"`
	CountryCode string  `json:"country_code,omitempty"`
	Severity    string  `json:"severity"`
	Role        string  `json:"role,omitempty"`
	Lat         float64 `json:"lat,omitempty"`
	Lng         float64 `json:"lng,omitempty"`
}

// IncidentGraphEdge links two alert nodes with an explainable reason.
type IncidentGraphEdge struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

// IncidentGraph is a lightweight star-plus-peer relation graph for analyst review.
type IncidentGraph struct {
	Nodes []IncidentGraphNode `json:"nodes"`
	Edges []IncidentGraphEdge `json:"edges"`
}

// IncidentGeoSummary aggregates geography across incident members.
type IncidentGeoSummary struct {
	CountryCodes []string `json:"country_codes"`
	Countries    []string `json:"countries,omitempty"`
}

type SignalLane string

const (
	SignalLaneAlarm SignalLane = "alarm"
	SignalLaneIntel SignalLane = "intel"
	SignalLaneInfo  SignalLane = "info"
)

type Triage struct {
	RelevanceScore  float64         `json:"relevance_score"`
	Threshold       float64         `json:"threshold,omitempty"`
	Confidence      string          `json:"confidence,omitempty"`
	Disposition     string          `json:"disposition,omitempty"`
	PublicationType string          `json:"publication_type,omitempty"`
	WeakSignals     []string        `json:"weak_signals,omitempty"`
	Metadata        *TriageMetadata `json:"metadata,omitempty"`
	Reasoning       string          `json:"reasoning,omitempty"`
}

type TriageMetadata struct {
	Author                 string   `json:"author,omitempty"`
	Tags                   []string `json:"tags,omitempty"`
	NoiseDecision          string   `json:"noise_decision,omitempty"`
	NoisePolicyVersion     string   `json:"noise_policy_version,omitempty"`
	NoisePolicyVariant     string   `json:"noise_policy_variant,omitempty"`
	NoiseBlockScore        float64  `json:"noise_block_score,omitempty"`
	NoiseScore             float64  `json:"noise_score,omitempty"`
	NoiseActionability     float64  `json:"noise_actionability_score,omitempty"`
	NoiseReasons           []string `json:"noise_reasons,omitempty"`
	NoiseDecisionTimestamp string   `json:"noise_decision_ts,omitempty"`
}

type DuplicateSample struct {
	Title string `json:"title"`
	Count int    `json:"count"`
}

type DuplicateAudit struct {
	SuppressedVariantDuplicates     int               `json:"suppressed_variant_duplicates"`
	SuppressedCrossSourceDuplicates int               `json:"suppressed_cross_source_duplicates"`
	RepeatedTitleGroupsInActive     int               `json:"repeated_title_groups_in_active"`
	RepeatedTitleSamples            []DuplicateSample `json:"repeated_title_samples"`
}

type SourceHealthEntry struct {
	SourceID         string `json:"source_id"`
	AuthorityName    string `json:"authority_name"`
	Type             string `json:"type"`
	Status           string `json:"status"`
	FetchedCount     int    `json:"fetched_count"`
	FeedURL          string `json:"feed_url"`
	Error            string `json:"error,omitempty"`
	ErrorClass       string `json:"error_class,omitempty"`
	NeedsReplacement bool   `json:"needs_replacement,omitempty"`
	DiscoveryAction  string `json:"discovery_action,omitempty"`
	StartedAt        string `json:"started_at"`
	FinishedAt       string `json:"finished_at"`
	ActiveCount      int    `json:"active_count,omitempty"`
	FilteredCount    int    `json:"filtered_count,omitempty"`
	// Cache metadata — not serialised to JSON, used internally to
	// populate source_watermarks so the next cycle can do conditional GET.
	RespETag         string `json:"-"`
	RespLastModified string `json:"-"`
}

type SourceReplacementCandidate struct {
	SourceID        string `json:"source_id"`
	AuthorityName   string `json:"authority_name"`
	Type            string `json:"type"`
	FeedURL         string `json:"feed_url"`
	BaseURL         string `json:"base_url,omitempty"`
	Country         string `json:"country,omitempty"`
	CountryCode     string `json:"country_code,omitempty"`
	Region          string `json:"region,omitempty"`
	AuthorityType   string `json:"authority_type,omitempty"`
	Category        string `json:"category,omitempty"`
	Error           string `json:"error,omitempty"`
	ErrorClass      string `json:"error_class,omitempty"`
	DiscoveryAction string `json:"discovery_action,omitempty"`
	LastAttemptAt   string `json:"last_attempt_at,omitempty"`
}

type SourceHealthDocument struct {
	GeneratedAt             string                       `json:"generated_at"`
	CriticalSourcePrefixes  []string                     `json:"critical_source_prefixes"`
	FailOnCriticalSourceGap bool                         `json:"fail_on_critical_source_gap"`
	TotalSources            int                          `json:"total_sources"`
	SourcesOK               int                          `json:"sources_ok"`
	SourcesError            int                          `json:"sources_error"`
	DuplicateAudit          DuplicateAudit               `json:"duplicate_audit"`
	ReplacementQueue        []SourceReplacementCandidate `json:"replacement_queue"`
	Sources                 []SourceHealthEntry          `json:"sources"`
}

type SourceReplacementDocument struct {
	GeneratedAt string                       `json:"generated_at"`
	Sources     []SourceReplacementCandidate `json:"sources"`
}

type SourceCandidate struct {
	URL           string `json:"url"`
	AuthorityName string `json:"authority_name,omitempty"`
	AuthorityType string `json:"authority_type,omitempty"`
	Category      string `json:"category,omitempty"`
	Country       string `json:"country,omitempty"`
	CountryCode   string `json:"country_code,omitempty"`
	Region        string `json:"region,omitempty"`
	BaseURL       string `json:"base_url,omitempty"`
	Notes         string `json:"notes,omitempty"`
}

type SourceCandidateDocument struct {
	GeneratedAt string            `json:"generated_at,omitempty"`
	Sources     []SourceCandidate `json:"sources"`
}
