# kafSIEM Documentation

kafSIEM is an edge-deployable operations intelligence platform. It builds an
entity graph from Kafka agent traffic and OSINT feeds, stores state in SQLite,
and serves analyst workflows through a web UI and OpenAPI.

## Start here

| Goal | Document |
|------|----------|
| Product overview and quick start | [README](../README.md) |
| Local dev targets (`make help`) | [Makefile](../Makefile) |
| System design and package layout | [architecture.md](architecture.md) |
| Docker, VM, installer, collector roles | [operations.md](operations.md) |
| Kafka observer, volumes, backup, replay | [agentops-operator-guide.md](agentops-operator-guide.md) |
| OpenAPI clients (TypeScript, Go) | [api-clients.md](api-clients.md) |
| API error types (RFC 9457) | [agentops-api-errors.md](agentops-api-errors.md) |

## Operating modes

| Mode | `UI_MODE` | Summary |
|------|-----------|---------|
| OSINT | `OSINT` | External intelligence: alerts, globe, attack-relation clusters |
| Operations | `AGENTOPS` | Kafka flow tracking, entity graph, ontology desk |
| Fusion | `HYBRID` | Operations plus OSINT correlation in one UI |

## Domain packs

Packs declare ontology, detectors, queries, views, map layers, and reports as
YAML. No pack executable code. Restart services to change active packs.

| Pack | Document | Use case |
|------|----------|----------|
| Drones | [packs/drones.md](packs/drones.md) | Fleet readiness, sorties, EW, software, signoff |
| SCADA | [packs/scada.md](packs/scada.md) | Plant, device, change audit, alarms, firmware, CVE |

Pack sources live under [`packs/`](../packs/).

## OSINT

| Topic | Document |
|-------|----------|
| Alert categories and UI | [userguide.md](userguide.md) |
| Attack relations and clustering | [userguide.md#attack-relations-clusters](userguide.md#attack-relations-clusters), [architecture.md#osint-attack-relations](architecture.md#osint-attack-relations) |
| Source vetting | [source-vetting.md](source-vetting.md) |
| ACLED integration | [acled.md](acled.md) |
| Collector migration | [collector-migration.md](collector-migration.md) |

OSINT incidents API (collector proxy): `GET /api/osint/incidents`,
`GET /api/osint/incidents/{id}`.

## Configuration

| Topic | Document |
|-------|----------|
| Minimal runtime env | [.env.example](../.env.example) |
| Advanced tuning | [advanced-config.md](advanced-config.md) |
| v1 to v2 upgrade | [upgrades/v1-to-v2.md](upgrades/v1-to-v2.md) |

## API reference

Generated OpenAPI: [api/openapi.yaml](../api/openapi.yaml)

Key `/api/v1` surfaces:

- `GET /entities/{type}/{id}` plus neighborhood, provenance, geometry, timeline
- `GET /flows`, `GET /flows/{id}/messages`, tasks, traces
- `GET /graph/path`, `GET /search`
- `GET /map/layers`, `GET /map/features`
- `GET /ontology/types`, `GET /ontology/packs`
- `GET /replays`, `POST /replays`

Legacy OSINT routes under `/api/*` proxy to the collector where configured.