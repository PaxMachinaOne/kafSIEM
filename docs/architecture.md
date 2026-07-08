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

## OSINT incident links

Active OSINT alerts can carry an `incident` block and a parallel
`incidents.json` index. The collector builds clusters from:

- cross-source fingerprint similarity (existing Jaccard dedup signals)
- shared CVE identifiers in titles
- shared actor entities for terrorism, conflict, cyber, and maritime categories

Primary alerts in a cluster expose `related_alert_ids` and `link_reasons`.
The OSINT alert detail drawer renders this as a collapsible linked-incident
panel without adding a new top-level UI mode.