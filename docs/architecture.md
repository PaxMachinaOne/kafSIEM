# Architecture

kafSIEM is an entity-centric operations and fusion platform. It consumes
Kafka-observed agent traffic and OSINT feeds, persists evidence in SQLite, and
exposes analyst workflows through a typed API and React UI.

Integration contract for external systems: OpenAPI, ontology endpoints,
pack-defined types, provenance, map features, and graph neighborhoods.

## Product boundary

kafSIEM is the product in this repository.

| External | Role |
|----------|------|
| KafScale | Kafka transport spine. kafSIEM reads from it. |
| KafClaw | Agent and workflow producers. Emit envelopes on group topics. |
| Enterprise platforms | Optional consumers of kafSIEM graph and ontology APIs |

Internal concepts:

- **Operations observer** (`internal/agentops/`): Kafka consumer, replay,
  policy, SQLite store, KafClaw envelope handling. Code and env still use the
  `AgentOps` name.
- **Packs** (`packs/`, `internal/packs/`): Constrained domain interfaces. YAML
  only. Not a plugin runtime.

Shipped packs:

- `drones`: unmanned systems readiness, sortie, EW, software, signoff
- `scada`: plant, device, change, alarm, firmware, vulnerability, session

## Operating modes

| Product name | Runtime `UI_MODE` | Data sources |
|--------------|-------------------|--------------|
| OSINT | `OSINT` | Curated feeds, browser scrape, optional LLM gates |
| Operations | `AGENTOPS` | Kafka group traffic, packs, SQLite graph |
| Fusion | `HYBRID` | Both. UI correlates flows with OSINT alerts heuristically |

## Package layout

```text
cmd/kafsiem-collector/   ingest binary (OSINT + Kafka observer)
cmd/kafsiem-api/         analyst API binary (read path)
cmd/pack-docs/           generated pack reference docs
internal/agentops/       Kafka observer, store, policy, envelopes
internal/graph/          entities, edges, provenance, geometry, queries
internal/packs/          pack loader and validation
internal/kafsiemapi/     HTTP handlers for /api/v1
internal/collector/      OSINT fetch, normalize, noise gate, output
packs/                   bundled drones and SCADA declarations
src/agentops/            Operations and Fusion UI
src/osint/               OSINT UI
api/                     OpenAPI spec generator and generated contract
```

## Runtime topology

Docker Compose runs four application services plus shared volumes:

```text
browser          headless Chrome bridge for scrape sources
collector        writer: OSINT JSON + agentops.db
kafsiem-api      reader: /api/v1 analyst resources
kafsiem          Caddy SPA, reverse proxy to kafsiem-api
```

Data path for Operations mode:

```text
KafClaw agents
      |
      v
KafScale / Kafka topics
      |
      v
cmd/kafsiem-collector
      |  decode envelope or LFS pointer
      |  update flows, tasks, traces
      |  append entities and edges
      v
/data/agentops.db (+ WAL/SHM)
      |
      v
cmd/kafsiem-api  --->  Caddy + React desk
```

The collector owns ingest and writes. The analyst API serves reads, search,
detector execution, and replay request enqueue. It does not mutate the live
Kafka consumer group or rewrite observed records.

Legacy OSINT endpoints (`/api/health`, `/api/search`, and similar) reverse
proxy to the collector internal API on port 3001.

## Graph model

SQLite tables in `internal/graph/schema/schema.sql`:

| Table | Purpose |
|-------|---------|
| `entities` | Typed objects. ID format `type:canonical_id` |
| `edges` | Relationships with `valid_from`, optional `valid_to`, `evidence_msg` |
| `provenance` | Ingest and policy decisions per subject |
| `entity_geometry` | GeoJSON features and bounding boxes |

Core entity types from Kafka ingest: `agent`, `task`, `trace`, `topic`,
`correlation`. Pack entity types (for example `platform`, `device`, `fault`)
are declared in pack YAML and populated by domain ingest or test fixtures.

Every accepted Kafka record can produce graph edges that reference
`messages(record_id)` for audit trail.

## Storage contract

Operations state path: `/data/agentops.db` in Docker.

WAL mode requires all three files in backup and restore:

- `agentops.db`
- `agentops.db-wal`
- `agentops.db-shm`

Volume mounts:

| Mount | Contents |
|-------|----------|
| `/config` | `agentops_policy.yaml`, UI policy |
| `/data` | `agentops.db`, OSINT JSON outputs, replay metadata |
| `/packs` | Active pack directories (read-only) |

## API contract

Versioned under `/api/v1`:

- Entity profile, neighborhood, provenance, geometry, timeline
- Graph path lookup
- Flow list, detail, messages, tasks, traces
- Replay list and create
- Map layers and GeoJSON features
- Ontology types and packs
- Typed search (includes pack detector SQL)

`api/openapi.yaml` is generated from `api/specgen/specgen.go`. TypeScript
client: `src/agentops/lib/api-client/`.

## Pack contract

```text
packs/<name>/
  pack.yaml           entity_types, edge_types
  detectors/*.yaml    SQL over named views
  queries/*.yaml      analyst query templates
  views/*.yaml        entity profile field layout
  maps/layers.yaml    map overlay config
  reports/*.md.tmpl   signoff and incident report templates
```

Validation runs at API and collector startup. No hot reload. No pack-local
executable code.

Generated references: [packs/drones.md](packs/drones.md),
[packs/scada.md](packs/scada.md).

## Search and integration keywords

Entity graph, Kafka observer, SQLite analyst API, edge SIEM, drone fleet
ontology, SCADA change audit, OSINT fusion, provenance trail, OpenAPI
operations intelligence, KafClaw envelope, replay consumer group.

Public positioning: complementary operations and fusion layer. Not a vendor
platform clone. Stable OpenAPI for external client generation.

## OSINT attack relations

OSINT mode and the public demo surface **corroborated attack clusters**: when
multiple independent sources describe the same cyber incident, terror plot,
maritime event, or conflict development, the collector links them into an
explainable relation bundle. This is separate from the Operations entity graph
(`internal/graph/`) but uses the same analyst pattern: typed objects, explicit
edges, and provenance-friendly `link_reasons`.

### Pipeline

```text
fetch + normalize
      |
      v
deduplicate (within-source only)
      |
      v
ApplyIncidentLinks          # union-find clustering + anchor corroboration
      |
      v
FinalizeActiveAlerts        # cross-source dedup AFTER clustering
      |
      v
alerts.json + incidents.json + osint_incidents (SQLite)
      |
      v
GET /api/osint/incidents[/{id}]  --->  OSINT Relations UI + Alert Detail drawer
```

`FinalizeActiveAlerts` runs incident linking **before** cross-source dedup so
Jaccard-similar corroborators are not removed before they can form a cluster.
Incident cluster members that share an `incident_id` are retained in the active
feed for analyst visibility.

Implementation: `internal/collector/normalize/incidents.go`,
`relation_anchors.go`, `attack_types.go`, `incident_overview.go`.

### Cluster link dimensions

| Reason prefix | Meaning | Typical attack lens |
|---------------|---------|---------------------|
| `cross_source:jaccard:` | Cross-source narrative similarity (24h) | general, conflict, terror |
| `shared_cve:` | Same CVE in titles (14d) | cyber |
| `shared_entity:` | Same actor within category (7d) | terror, conflict, maritime |
| `cross_category_entity:` | Known actor across categories (7d) | terror, hybrid |
| `shared_country:` | Same `event_country_code` + weak overlap (7d) | conflict, terror, maritime |
| `anchor:kev:` / `anchor:epss:` | CISA KEV / FIRST EPSS corroboration | cyber |
| `anchor:sanctioned:` / `anchor:known_actor:` | Sanctions / actor registry | terror |
| `anchor:travel_warning:` / `anchor:conflict_data:` | Travel advisory / ACLED-UCDP geo | conflict, terror |
| `shared_malware:` | URLhaus/Feodo IOC overlap (domain, family, hash, IP) | cyber |
| `targets_sector:` | ICS/energy sector keyword overlap | cyber |
| `sanctioned_entity:` | OpenSanctions ↔ terror tip actor match | terror |
| `anchor:malware:` | URLhaus/Feodo feed corroboration | cyber |

Clustering is deterministic (union-find, hashed `inc-id`). No LLM clustering.

### Attack type classification

Each incident summary carries `attack_type` for the public Relations lens:

| `attack_type` | Detection signal |
|---------------|------------------|
| `cyber` | Shared CVEs or KEV/EPSS anchors |
| `terror` | Terror category, shared/sanctioned actors, known-actor anchors |
| `maritime` | `maritime_security` category cluster |
| `conflict` | `conflict_monitoring` / humanitarian security cluster |
| `travel` | `travel_warning` cluster |
| `hybrid` | Cyber signals plus terror or conflict signals |
| `general` | Multi-source corroboration without a dominant lens |

`ClassifyAttackType()` in `attack_types.go` derives the lens from member
alerts, categories, and `link_reasons`.

### Alert and index schema

Every cluster member alert can carry an `incident` block:

```json
{
  "incident_id": "inc-…",
  "member_count": 3,
  "primary_alert_id": "…",
  "role": "primary",
  "related_alert_ids": ["…"],
  "link_reasons": ["shared_cve:CVE-2026-1234"],
  "shared_cves": ["CVE-2026-1234"],
  "shared_entities": ["Al-Shabaab"],
  "shared_countries": ["SO"]
}
```

Parallel index: `incidents.json` beside `alerts.json`. Persisted table:
`osint_incidents` in the collector SQLite registry (`internal/sourcedb/`).

### Relation graph (analyst overview)

Detail API responses include a lightweight relation graph built at read time:

| Part | Content |
|------|---------|
| `timeline` | Member alerts ordered by `first_seen` |
| `geo` | Aggregated `country_codes` / country names |
| `graph.nodes` | Alerts plus typed nodes: `actor`, `cve`, `country` |
| `graph.edges` | `attributed_to`, `exploits`, `located_in`, corroboration to primary |

Endpoints (proxied via `kafsiem-api` legacy proxy):

- `GET /api/osint/incidents?limit=50`
- `GET /api/osint/incidents/{id}`

### OSINT UI surfaces

| Surface | Path | Purpose |
|---------|------|---------|
| **Relations** | Header toggle `Overview` / `Relations` | Browse clusters by attack type |
| **Alert queue** | `src/components/AlertFeed.tsx` | `N linked` / `corroborates` badges |
| **Alert detail** | `IncidentLinks` + `IncidentRelationGraph` | Reasons, timeline, typed graph |
| **Intel overview** | `FeedDirectory` | Linked-incident count and filter chip |
| **Globe** | `GlobeView` | Tooltip on incident anchors |

Frontend hooks: `useIncidents`, `useIncidentDetail`. Demo fixtures:
`public/demo/alerts.json`, `public/demo/incidents.json` (`make demo-osint` /
`?demo=osint`).

### Open-data relation anchors

Structured feeds corroborate clusters without forming edges alone:

- CISA KEV, FIRST EPSS, NVD JSON
- UN/OFAC sanctions XML, OpenSanctions NDJSON
- URLhaus, Feodo (malware IOC anchors and `shared_malware` linking)
- IMB piracy HTML, ACLED/UCDP conflict data
- Terror actor aliases: `registry/terror_actor_aliases.json`

Anchors add `anchor:*` reasons via `ApplyAnchorCorroboration()` in
`relation_anchors.go`.

### Fusion mode integration

Fusion (`HYBRID`) links Operations Kafka flows to incident clusters through
`src/agentops/lib/hybrid.ts`. Flow indicators (CVE, sector, geography, actor)
match alert text and `incident.shared_cves` / `incident.shared_entities`.
Incident-backed matches rank higher in the Fusion Context block with
corroboration counts.

### Planned relation dimensions

| Dimension | Status |
|-----------|--------|
| Malware IOC overlap (URLhaus/Feodo) | implemented (`shared_malware`, `anchor:malware`) |
| Sector targeting keywords (ICS/energy) | implemented (`targets_sector`) |
| Sanctioned entity auto-link | implemented (`sanctioned_entity`) |
| Globe edge overlay between incident members | planned |
| STIX export from incident graph | planned |