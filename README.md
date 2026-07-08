# kafSIEM

Edge-ready operations intelligence with an evidence-linked entity graph.

kafSIEM watches Kafka agent traffic and OSINT feeds, materializes entities and
relationships in SQLite, and serves analyst workflows through a web desk and
typed OpenAPI. Deploy with Docker on a single host. No cluster database
required.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![OpenAPI](https://img.shields.io/badge/API-OpenAPI-green)](api/openapi.yaml)
[![Docker](https://img.shields.io/badge/deploy-docker--compose-blue)](docker-compose.yml)

Keywords: entity graph, Kafka SIEM, OSINT dashboard, drone fleet operations,
SCADA security, edge deployment, ontology packs, provenance, SQLite analyst API.

## Screenshots

<p align="center">
  <a href="public/images/Scalytics-OSINT-Prediction.png">
    <img src="public/images/Scalytics-OSINT-Prediction.png" alt="kafSIEM OSINT globe and alert feed" width="32%" />
  </a>
  <a href="public/images/Scalytics-Ontology-Drones.png">
    <img src="public/images/Scalytics-Ontology-Drones.png" alt="kafSIEM Operations desk with drones ontology graph" width="32%" />
  </a>
  <a href="public/images/Scalytics-Ontology-SCADA.png">
    <img src="public/images/Scalytics-Ontology-SCADA.png" alt="kafSIEM Operations desk with SCADA ontology graph" width="32%" />
  </a>
</p>
<p align="center">
  <strong>OSINT</strong> | <strong>Operations / Drones</strong> | <strong>Operations / SCADA</strong>
</p>

## Try in 30 seconds

No Kafka, API keys, or Docker required.

```bash
git clone https://github.com/scalytics/kafSIEM.git && cd kafSIEM
npm install
npm run demo:ontology:drones   # unmanned systems ontology desk
npm run demo:ontology:scada    # SCADA / OT ontology desk
npm run demo:fusion            # operations plus OSINT correlation
```

Opens the Operations or Fusion desk with typed mock API data. For OSINT attack
relations without Docker, use `npm run dev` and open `/?demo=fusion` — includes
cyber and terror incident clusters in the Relations panel.

## What you get

- **Entity graph** stored in SQLite: platforms, faults, devices, agents, tasks.
  Graph edges can cite the source Kafka record.
- **Analyst desk**: flow queue, topology graph, map, replay studio, entity
  profiles, provenance drawer.
- **Domain packs**: YAML ontology for drones and SCADA. Detectors, queries,
  views, map layers, report templates. No pack executable code.
- **Typed API**: `/api/v1/...` with generated [OpenAPI](api/openapi.yaml).
  Integrates with existing enterprise platforms.
- **Edge deployment**: collector writes, API reads, shared volume. Docker
  Compose or Helm.

## Who it is for

**Unmanned systems teams** tracking readiness, sorties, EW events, software
lineage, and signoff evidence across a fleet.

**SCADA and critical infrastructure teams** connecting plants, devices, change
audit, alarms, firmware, vulnerabilities, and engineer sessions.

| Pack | Example questions |
|------|-------------------|
| [Drones](docs/packs/drones.md) | What changed since last signoff? Is this fault fleet-wide? Which platforms run software version X? |
| [SCADA](docs/packs/scada.md) | Which changes lack a work order? Is firmware drifting on safety PLCs? What CVEs affect live devices? |

## How it works

```text
KafClaw agents
      |
      v
KafScale / Kafka
      |
      v
kafsiem-collector  --->  /data/agentops.db (+ WAL/SHM)
      |                           |
      | legacy /api/*             v
      +---------------->  kafsiem-api  --->  Caddy + web UI
```

The collector ingests OSINT sources and, when enabled, consumes Kafka traffic.
It is the sole writer for observed operational state. `kafsiem-api` serves
read-only analyst resources and enqueues replay requests. See
[Architecture](docs/architecture.md).

## Operating modes

| Product name | `UI_MODE` | Purpose |
|--------------|-----------|---------|
| OSINT | `OSINT` | Globe-first intelligence, alert feeds, attack-relation clusters |
| Operations | `AGENTOPS` | Kafka agent flow tracking and ontology desk |
| Fusion | `HYBRID` | Operations plus heuristic OSINT correlation |

Set mode via `UI_MODE` and mounted policy files. User-facing copy uses OSINT,
Operations, and Fusion. Runtime env values stay `AGENTOPS` and `HYBRID` for
compatibility.

## Quick start (Docker)

```bash
cp .env.example .env
docker compose up --build
```

UI: `http://localhost:8080`

Make targets for local HTTP dev:

```bash
make dev-start
make dev-stop
make dev-restart
make dev-logs
```

## Remote install

```bash
wget -qO- https://raw.githubusercontent.com/scalytics/kafSIEM/main/deploy/install.sh | bash
```

The installer checks Docker, clones or updates the repo, prompts for profile
(OSINT, Operations, or Fusion), site address, and profile-specific settings,
then starts GHCR images.

## API example

```bash
curl -s http://localhost:8080/api/v1/ontology/packs | jq .
curl -s http://localhost:8080/api/v1/flows | jq .
curl -s http://localhost:8080/api/v1/entities/platform/auv-7 | jq .
```

Full contract: [api/openapi.yaml](api/openapi.yaml). Client notes:
[docs/api-clients.md](docs/api-clients.md).

## Stack context

| Component | Role |
|-----------|------|
| **KafScale** | External Kafka transport. kafSIEM consumes from it. |
| **KafClaw** | External agent plane. Emits group envelopes on Kafka topics. |
| **kafSIEM** | Observer, graph store, API, UI, packs (this repository). |

kafSIEM complements enterprise intelligence platforms. It exposes typed entity
and graph APIs, pack-defined ontology, and provenance back to source records.

## Documentation

| Topic | Document |
|-------|----------|
| Full doc index | [docs/README.md](docs/README.md) |
| Architecture | [docs/architecture.md](docs/architecture.md) |
| Operations / Docker / VM | [docs/operations.md](docs/operations.md) |
| Operations Kafka config | [docs/agentops-operator-guide.md](docs/agentops-operator-guide.md) |
| API clients | [docs/api-clients.md](docs/api-clients.md) |
| Drones pack | [docs/packs/drones.md](docs/packs/drones.md) |
| SCADA pack | [docs/packs/scada.md](docs/packs/scada.md) |
| OSINT user guide | [docs/userguide.md](docs/userguide.md) |
| Advanced env tuning | [docs/advanced-config.md](docs/advanced-config.md) |
| Minimal env template | [.env.example](.env.example) |

## Development

```bash
make check
make ci
make docker-build
```

Node `25.8.1` and npm `11.11.0` are pinned in `package.json`, `.nvmrc`, and
`.node-version`. The Go collector powers scheduled feed refresh, Docker
runtime, and local collection commands.

OSINT-only local dev without Docker:

```bash
npm install
npm run fetch:alerts:watch   # live collector JSON (optional)
npm run dev                  # or ?demo=fusion for bundled relation demo
```

Browse corroborated clusters: header **Relations** → filter by attack type
(cyber, terror, maritime, conflict). See
[docs/userguide.md](docs/userguide.md#attack-relations-clusters).

## License

Apache-2.0. See [LICENSE](LICENSE).