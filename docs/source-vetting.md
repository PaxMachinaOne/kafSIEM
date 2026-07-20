<!--
Copyright 2024 ff, Scalytics, Inc. - https://www.scalytics.io
SPDX-License-Identifier: Apache-2.0
-->

# Source Vetting

## Runtime Model

The crawler and source vetter now have separate roles:

- `registry/source_candidates.json`: untrusted crawler intake
- `registry/sources.db`: vetted live sources only
- `registry/source_dead_letter.json`: terminal dead-letter queue, never crawled again

Discovery reads `source_candidates.json`, probes for RSS/Atom or durable HTML listing pages, samples content, and optionally calls an LLM source vetter. Only approved sources are promoted into `sources.db`. Promoted candidates are removed from the candidate queue.

If `SEARCH_DISCOVERY_ENABLED=true`, discovery also uses the configured OpenAI-compatible model as a narrow search accelerator. It asks for a small number of official candidate URLs for a capped set of agencies and feeds those URLs back into the same candidate queue and vetting pipeline.

## LLM Endpoint Contract

Every OSINT LLM workload uses the same OpenAI-compatible `chat/completions`
contract. There are no vendor SDKs or provider-specific routing branches. This
works directly with compatible services such as:

- OpenAI
- Mistral
- xAI
- Scalytics Copilot
- vLLM
- Ollama

Point `LLM_BASE_URL` at the provider's compatibility endpoint or at a gateway
and configure the model IDs it exposes. Anthropic and Gemini currently provide
compatibility endpoints, but both describe them as limited compared with their
native APIs. `LLM_PROVIDER` is an informational label; it never changes request
behavior.

## Search Discovery and Token Economics

The discovery pipeline uses browser-backed DuckDuckGo search first. The LLM is
only asked about the remaining uncovered targets, with both target count and
URLs per target capped. Returned URLs still enter the normal probe, hygiene,
and vetting pipeline.

This saves more tokens than asking a model to research the open web on every
cycle: deterministic search retrieves URLs, kafSIEM fetches and deduplicates
the source data, and the model receives only compact candidates or evidence.
The generic `chat/completions` contract does not enable vendor-specific web
tools. A provider may ground a model internally, but kafSIEM never assumes it
did so.

Recommended use of the LLM fallback:

- generate a small set of candidate URLs for a specific agency, country, or sector
- pass those URLs into the candidate queue
- let the crawler, deterministic hygiene, and source vetter decide whether they are usable

Do not use search-capable models as direct truth sources or direct promotion sources.

### Token-Safe Search

Use the configured model in a narrow, token-safe way:

- ask for a small number of candidate URLs, not a long report
- constrain by agency, country, and sector
- request only official or high-confidence source URLs
- avoid broad prompts like "find everything about police feeds worldwide"
- prefer short JSON output with URLs and a one-line reason

Good pattern:

- input: `Find up to 5 official feed/API/newsroom URLs for Bundeskriminalamt related to wanted suspects or public appeals. Return JSON only.`
- output: small candidate list

Bad pattern:

- input: `Research German law enforcement internet presence in detail and summarize everything.`

## Environment Variables

```dotenv
SEARCH_DISCOVERY_ENABLED=true
SEARCH_DISCOVERY_MAX_TARGETS=4
SEARCH_DISCOVERY_MAX_URLS_PER_TARGET=3
HTTP_TIMEOUT_MS=60000
SOURCE_VETTING_ENABLED=true
LLM_PROVIDER=xai
LLM_BASE_URL=https://api.x.ai/v1
LLM_API_KEY=
LLM_MODEL=grok-4.3
LLM_MODEL_FALLBACKS=grok-4.3-latest,grok-latest
SOURCE_VETTING_TEMPERATURE=0
SOURCE_VETTING_MAX_SAMPLE_ITEMS=6
ALERT_LLM_ENABLED=true
ALERT_LLM_MODEL=grok-4.3
ALERT_LLM_MODEL_FALLBACKS=grok-4.3-latest,grok-latest
ALERT_LLM_MAX_ITEMS_PER_SOURCE=4
LLM_MODEL_DISCOVERY_ENABLED=true
LLM_MODEL_REFRESH_HOURS=168
LLM_MAX_OUTPUT_TOKENS=1200
```

Put the real API key only in your local `.env`. Do not commit it.

### Model discovery and failover

The LLM runtime is OpenAI-compatible and shared by source vetting, search
discovery, alert classification, conflict briefs, and terror analysis. At
startup it attempts `GET /models` using the configured base URL and bearer
token. Successful inventories are cached for seven days by default.

The configured model wins when available, followed by the workload's ordered
fallback list. If neither is present, kafSIEM conservatively selects a text/chat
model and avoids embedding, image, audio, moderation, reranking, realtime, and
code-specialized models. A completion-time model 404 forces an inventory
refresh and one retry with a newly resolved model. Failure or absence of the
models endpoint is non-fatal for compatible gateways that only implement chat
completions.

When inventory access is forbidden, a model 404 advances through the explicit
fallback list without requiring `/models`. kafSIEM does not ship vendor model
aliases because those become stale. Set `LLM_MODEL_FALLBACKS` and, when needed,
`ALERT_LLM_MODEL_FALLBACKS` explicitly. The provider label never changes the
endpoint protocol.

The canonical shared settings are `LLM_PROVIDER`, `LLM_BASE_URL`, `LLM_API_KEY`,
`LLM_MODEL`, and `LLM_MODEL_FALLBACKS`. Existing deployments using the legacy
`SOURCE_VETTING_PROVIDER`, `SOURCE_VETTING_BASE_URL`, `SOURCE_VETTING_API_KEY`,
`SOURCE_VETTING_MODEL`, and `SOURCE_VETTING_MODEL_FALLBACKS` names continue to
work; canonical values take precedence when both are present.

`GET /api/health` reports configured and resolved models, inventory timestamps,
last errors, token usage, and provider-reported cost when available.

### Evidence-grounded terror analysis

Terror analysis does not ask the model to invent active regions or coordinates.
The collector extracts terror signals from its web, RSS, GDELT, and official
source results, collapses incident and duplicate-title results, ranks them by
severity, recency, and incident source count, and sends only compact evidence
lines. Full pages and alert histories are excluded.

The default prompt budget is capped at 24 evidence items, four per country, and
the eight highest-ranked countries per request.
New critical, alarm-lane, or multi-source evidence can trigger an early refresh.
Otherwise analysis runs daily when evidence changes and reuses unchanged output
for up to 72 hours. Returned country assessments must cite valid alert IDs;
geography remains deterministic.

## Example Endpoints

OpenAI:

```dotenv
LLM_PROVIDER=openai
LLM_BASE_URL=https://api.openai.com/v1
LLM_API_KEY=your-openai-key
LLM_MODEL=your-available-model-id
```

Mistral:

```dotenv
LLM_PROVIDER=mistral
LLM_BASE_URL=https://api.mistral.ai/v1
LLM_API_KEY=your-mistral-key
LLM_MODEL=your-available-model-id
```

xAI:

```dotenv
LLM_PROVIDER=xai
LLM_BASE_URL=https://api.x.ai/v1
LLM_API_KEY=your-xai-key
LLM_MODEL=grok-4.3
LLM_MODEL_FALLBACKS=grok-4.3-latest,grok-latest
ALERT_LLM_MODEL=grok-4.3
```

Scalytics Copilot:

```dotenv
LLM_PROVIDER=scalytics-copilot
LLM_BASE_URL=https://YOUR_SCALYTICS_COPILOT_URL/v1
LLM_API_KEY=your-copilot-key
LLM_MODEL=your-copilot-model
ALERT_LLM_MODEL=your-copilot-model
```

vLLM:

```dotenv
LLM_PROVIDER=vllm
LLM_BASE_URL=http://vllm-host:8000/v1
LLM_API_KEY=dummy
LLM_MODEL=your-served-model-id
```

Ollama:

```dotenv
LLM_PROVIDER=ollama
LLM_BASE_URL=http://localhost:11434/v1
LLM_API_KEY=dummy
LLM_MODEL=your-local-model-id
```

Anthropic OpenAI compatibility layer:

```dotenv
LLM_PROVIDER=anthropic
LLM_BASE_URL=https://api.anthropic.com/v1
LLM_API_KEY=your-anthropic-key
LLM_MODEL=your-available-claude-model-id
LLM_MODEL_FALLBACKS=another-available-claude-model-id
```

Anthropic recommends this compatibility layer for testing and comparison, not
as the long-term production path to every Claude feature. For production use,
either accept those compatibility limits or put a maintained OpenAI-compatible
gateway in front of the native API.

Gemini OpenAI compatibility layer:

```dotenv
LLM_PROVIDER=gemini
LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai
LLM_API_KEY=your-gemini-key
LLM_MODEL=your-available-gemini-model-id
LLM_MODEL_FALLBACKS=another-available-gemini-model-id
```

Gemini labels its OpenAI compatibility support beta. A gateway remains valid
when you need a stable organization-wide contract or native-only features.

## CLI Usage

Run the crawler and vetter once:

```bash
go run ./cmd/kafsiem-collector \
  --discover \
  --registry registry/sources.db \
  --candidate-queue registry/source_candidates.json \
  --replacement-queue registry/source_dead_letter.json \
  --search-discovery \
  --search-discovery-max-targets 4 \
  --search-discovery-max-urls 3 \
  --source-vetting \
  --source-vetting-provider xai \
  --source-vetting-base-url https://api.x.ai/v1 \
  --source-vetting-api-key "$LLM_API_KEY" \
  --source-vetting-model grok-4.3 \
  --alert-llm \
  --alert-llm-model grok-4.3
```

## Promotion Policy

The LLM does not bypass deterministic hygiene.

Sources are rejected before the LLM stage if they look like:

- local or municipal police
- generic institutional news
- low-signal public relations pages
- sources with no sample items to assess

Approved sources are promoted into `sources.db` with:

- `promotion_status`
- `source_quality`
- `operational_relevance`
- `level`
- `mission_tags`

The live watcher only loads `promotion_status = active`.

## Alert-Level LLM Gate

You can also enable an item-level LLM gate for ambiguous `html-list` sources.

When enabled, each candidate HTML item is sent to the same OpenAI-compatible endpoint with a short prompt that must return strict JSON:

- `yes`: whether the item is intelligence-relevant or just noise
- `translation`: a short English title
- `category_id`: the normalized category id if `yes = true`

If `yes = false`, the collector drops the item.
If `yes = true`, the collector uses the English title and category override during normalization.

RSS, Atom, and structured API sources stay on the deterministic collector path so the live watcher does not stall behind LLM latency.

Example:

```dotenv
ALERT_LLM_ENABLED=true
ALERT_LLM_MODEL=grok-4.3
ALERT_LLM_MAX_ITEMS_PER_SOURCE=4
```

This uses the same provider/base URL/API key as source vetting.

For xAI and similar reasoning-heavy models, keep `ALERT_LLM_MAX_ITEMS_PER_SOURCE` low and raise `HTTP_TIMEOUT_MS` above the default collector timeout. A practical starting point is:

```dotenv
HTTP_TIMEOUT_MS=60000
ALERT_LLM_MAX_ITEMS_PER_SOURCE=4
```

The same principle applies here: if your configured model supports search, use it to return a strict, short yes/no decision, a short English title, and a category id. Keep prompts short and outputs structured to avoid wasting tokens.

Equivalent xAI request shape:

```bash
curl https://api.x.ai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $LLM_API_KEY" \
  -d '{
    "messages": [
      {"role": "system", "content": "You are a test assistant."},
      {"role": "user", "content": "Testing. Just say hi and hello world and nothing else."}
    ],
    "model": "grok-4.3",
    "stream": false,
    "temperature": 0
  }'
```

Equivalent Scalytics Copilot request shape:

```bash
curl https://YOUR_SCALYTICS_COPILOT_URL/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $LLM_API_KEY" \
  -d '{
    "messages": [
      {"role": "system", "content": "You are a test assistant."},
      {"role": "user", "content": "Testing. Just say hi and hello world and nothing else."}
    ],
    "model": "your-copilot-model",
    "stream": false,
    "temperature": 0
  }'
```
