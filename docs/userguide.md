# kafSIEM OSINT User Guide

OSINT mode (`UI_MODE=OSINT`): alert categories, sources, globe view, search,
and noise controls. For Operations and Fusion modes see
[architecture.md](architecture.md) and [agentops-operator-guide.md](agentops-operator-guide.md).

## Alert Categories

kafSIEM classifies every alert into one of the following categories. Each category groups a specific type of intelligence and is sourced from relevant official feeds.

Each alert also carries a derived `subcategory` (for example `piracy`, `airstrike`, `money_laundering`, `earthquake`, `policy_update`) to improve clustering and analyst triage without expanding the left-panel primary category filters.

### Cyber Advisory
Vulnerability disclosures, patch advisories, and threat intelligence from national CERTs and cybersecurity agencies. Covers zero-days, actively exploited CVEs, ransomware campaigns, and critical infrastructure advisories.

**Sources:** CISA, BSI, CERT-EU, CERT.AT, NCSC-UK, ANSSI, ENISA, NVD/KEV, and 60+ national CERTs worldwide.

### Wanted Suspect
Active arrest warrants and wanted person notices from law enforcement agencies. Includes fugitives, persons of interest, and internationally wanted individuals.

**Sources:** Interpol Red Notices (newest 160 per run), FBI Most Wanted, Europol Most Wanted, BKA, national police agencies across Europe, Americas, and Asia-Pacific.

### Missing Person
Active missing person cases including children, endangered adults, and unidentified remains. Covers AMBER alerts and international missing person notices.

**Sources:** Interpol Yellow Notices (newest 160 per run), NCMEC, NamUs, BKA Vermisste, national police missing person feeds.

### Public Appeal
Police appeals for information from the public: witness calls, identification
requests, crime tip lines, and community safety notices.

**Sources:** Metropolitan Police, Police.uk, Polizei.de state feeds, Gendarmerie, FBI tips, and regional law enforcement across 30+ countries.

### Fraud Alert
Consumer fraud warnings, financial crime alerts, scam advisories, and money laundering notices from financial regulators and law enforcement.

**Sources:** FCA, BaFin, SEC, FINMA, Europol financial crime, ACCC Scamwatch, national consumer protection agencies.

### Intelligence Report
Strategic intelligence assessments, geopolitical analysis, and security briefings from think tanks and intelligence-adjacent organisations.

**Sources:** SIPRI, IISS, RUSI, Jane's, UN Security Council press, OSCE, NATO CCDCOE, national intelligence agency public releases.

### Legislative
Official sovereign-government statements and institutional policy announcements (head of state/government, parliament, MFA/defense channels). Most items are informational for briefing/trend analysis, but strategic escalation titles (for example declaration of war/state emergency) are routed into alarm workflows.

**Sources:** Curated sovereign official-statement seed layer, plus vetted government/legislative/diplomatic discovery sources.

### Travel Warning
Government-issued travel advisories and consular warnings. Covers security situations, health risks, and entry restrictions for countries and regions.

**Sources:** US State Department, UK FCDO, German Auswaertiges Amt, and other foreign ministry travel advisory feeds.

### Conflict Monitoring
Armed conflict tracking, ceasefire violations, military operations, and peace process updates from conflict zones worldwide. Includes structured event data with precise geo-coordinates for battles, explosions, and violence against civilians.

**Sources:** ACLED (Armed Conflict Location & Event Data), UN Peace & Security, SIPRI conflict data, OSCE monitoring missions, peacekeeping operation feeds.

### Humanitarian Security
Security incidents affecting humanitarian operations: aid worker safety, access
restrictions, and operational environment assessments in crisis zones.

**Sources:** ICRC field operations, ICRC IHL updates, UN OCHA, UNHCR, and humanitarian coordination feeds.

### Humanitarian Tasking
Active humanitarian missions, disaster response deployments, and relief operation updates.

**Sources:** UN Peacekeeping (Blue Helmets), UNOCHA coordination, UN humanitarian aid operations.

### Health Emergency
Disease outbreaks, pandemic updates, public health emergencies, and biosecurity alerts from health authorities.

**Sources:** WHO, ECDC, CDC, RKI, national public health agencies.

### Public Safety
Civil protection alerts, natural disaster warnings, critical infrastructure incidents, and emergency notifications.

**Sources:** National emergency management agencies, civil protection feeds, disaster response organisations.

### Emergency Management
Large-scale emergency coordination, disaster declarations, evacuation orders, and crisis management updates.

**Sources:** FEMA, BBK (German Federal Office of Civil Protection), EU Civil Protection Mechanism.

### Terrorism Tip
Counter-terrorism alerts, threat assessments, and public safety notices related to terrorism and extremism.

**Sources:** Europol TE-SAT, national counter-terrorism units, security service public advisories.

### Private Sector
Corporate security alerts, supply chain disruptions, and industry-specific threat intelligence relevant to private sector operations.

**Sources:** Industry ISACs, sector-specific CERTs, corporate security advisory feeds.

---

## Severity Levels

Every alert is assigned a severity level based on keyword analysis of the title and content:

| Level | Colour | Criteria |
|-------|--------|----------|
| **Critical** | Red | Zero-days, ransomware, active exploitation, wanted fugitives, missing persons, AMBER alerts, emergencies |
| **High** | Orange | Vulnerabilities, compromises, phishing, fraud, urgent advisories, security warnings |
| **Medium** | Yellow | Arrests, charges, sentences, moderate-severity items |
| **Low** | Blue | Minor advisories, routine updates |
| **Informational** | Grey | Newsletters, info packets, guidance documents, educational material |

Keyword matching supports English and German (e.g., "Kritische Schwachstelle" = critical, "Sicherheitslücke" = high, "Infopaket" = informational).

---

## Interpol Notices

kafSIEM pulls the **newest 160 Red Notices** (wanted suspects) and **newest 160 Yellow Notices** (missing persons) from the Interpol public API per collector run. This limit is intentional to avoid data overflow and excessive API load.

- Red Notices: ~6,400 active notices globally
- Yellow Notices: ~4,000 active notices globally

Only the most recent window is fetched each cycle. Notices are pinned on the map to the suspect's nationality country rather than Interpol HQ in Lyon. Links point to the Interpol web view, not the raw API.

---

## Map

The map uses [CARTO](https://carto.com/) dark basemap tiles loaded from their CDN. An active internet connection is required for map rendering. Missing or slow-loading tiles indicate network connectivity issues to `basemaps.cartocdn.com`.

Alerts are plotted at event coordinates/country when resolvable. If event location confidence is low, fallback pinning uses source-country coordinates with low-confidence metadata.

---

## Attack relations (clusters)

kafSIEM links corroborating alerts from **different sources** into incident
clusters. This is the primary analyst feature for the public OSINT demo: detect
cyber campaigns, terror plots, maritime incidents, and conflict developments
from open feeds without manual copy-paste.

### How clusters form

The collector unions alerts when any of these hold (see
[architecture.md](architecture.md) for full detail):

- **Cross-source narrative match** — similar title fingerprints from different
  feeds within 24 hours
- **Shared CVE** — same CVE identifier across advisories (14-day window)
- **Shared actor** — same known group within a category (7-day window)
- **Cross-domain actor** — same registry actor across terror and conflict
  categories (e.g. tip line + ACLED event)
- **Shared geography** — same `event_country_code` with supporting text overlap
- **Open-data anchors** — KEV, EPSS, sanctions, travel warnings, conflict datasets

Each link produces an explainable `link_reason` string (no LLM clustering).

### Attack type lenses

Clusters are tagged with `attack_type` for filtering in the **Relations** panel:

| Lens | What it catches |
|------|-----------------|
| Cyber | CVE overlap, KEV/EPSS corroboration |
| Terror / extremist | Actor registry, sanctions, terror tips |
| Maritime | Piracy and maritime security feeds |
| Conflict | ACLED/UCDP-backed developments |
| Hybrid | Cyber plus terror or conflict signals in one cluster |

### Using the Relations UI

1. Open the OSINT console.
2. Click **Relations** in the header (next to Overview).
3. Filter by attack type or browse all clusters.
4. Click a cluster card to jump to the primary alert on the map and queue.
5. Open any linked alert and expand **Linked incident** for:
   - link reason chips
   - geography summary
   - relation graph (alerts, actors, CVEs, countries)
   - chronological timeline
   - corroborating peers (from feed + incidents API)

**Queue badges:** primary alerts show `N linked`; corroborating members show
`corroborates`. Use the linked-incident chip in the intel overview to filter the
queue to cluster members only.

### Incidents API

When the collector stack is running:

```bash
curl -s http://localhost:8080/api/osint/incidents | jq .
curl -s http://localhost:8080/api/osint/incidents/inc-demo-cve-12345 | jq .
```

Detail responses include `timeline`, `geo`, and `graph` for analyst overview.

### Local demo without Docker

```bash
make demo-osint
```

Opens the OSINT console at `/?demo=osint` with bundled fixtures. For a live
collector stack instead, use `make dev-start` and open `http://localhost:8080`.

Demo fixtures include **cyber** CVE and Dridex malware clusters, an **ICS/energy**
sector-targeting cluster, and a **terror** Al-Shabaab cross-domain cluster. Click
**Relations** to browse all four.

---

## Collector Cycle

The collector runs on a configurable interval (default: 15 minutes). Each run:

1. Fetches all active sources from the registry (~460+ curated sources)
2. Parses and normalizes alerts with severity and category classification
3. Deduplicates within-source variants
4. Reconciles with previous state (tracks new, active, and removed alerts)
5. Builds incident clusters and writes `alerts.json` + `incidents.json`
6. Persists incidents to SQLite (`osint_incidents`) when using the sqlite registry

Removed alerts (e.g., a resolved Interpol notice) are retained in state for 14 days before being purged.

---

## Stop Words (Global Noise Filter)

kafSIEM ships a global stop-word list at `registry/stop_words.json` that automatically excludes off-topic content from all feeds. Any alert whose title, summary, or tags contain a stop word is dropped before relevance scoring.

The default list filters out sports (football, basketball, cricket, FIFA, UEFA, etc.), entertainment (celebrity, Hollywood, Grammy, Oscar, etc.), lifestyle (recipes, horoscopes, astrology), and other non-OSINT noise.

### Customising the list

Edit `registry/stop_words.json` directly. It is a JSON file with a `stop_words`
array of case-insensitive substring terms. Restart the collector to pick up
changes.

```json
{
  "stop_words": [
    "football",
    "celebrity",
    "horoscope"
  ]
}
```

### Adding extra terms via environment

Set `STOP_WORDS` as a comma-separated list to add terms on top of the file:

```bash
STOP_WORDS="kardashian,tiktok dance,soap opera"
```

To use a different file path:

```bash
STOP_WORDS_PATH=/custom/path/stop_words.json
```

### How it works

Stop words are merged with per-source `exclude_keywords` from the source registry and applied in the same filter pass. Per-source keywords target a single feed; stop words apply globally across all sources. Both use case-insensitive substring matching against the combined title, summary, tags, and URL of each item.

---

## Regions

The dashboard supports region-scoped views:

| Region | Coverage |
|--------|----------|
| **Global** | All sources worldwide |
| **Europe** | EU/EEA member states, UK, Switzerland, Balkans, Eastern Europe |
| **North America** | US, Canada, Mexico |
| **South America** | Central and South America |
| **Asia** | East Asia, Southeast Asia, South Asia, Central Asia, Middle East |
| **Africa** | All African nations |
| **Oceania** | Australia, New Zealand, Pacific Islands |
| **Caribbean** | Caribbean island nations |
| **International** | Sources with global scope (Interpol, UN, ICRC) |

Region shortcuts in the header bar and the dropdown selector both filter the map and alert feed simultaneously.
