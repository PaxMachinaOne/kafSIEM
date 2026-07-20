<!--
Copyright 2024 ff, Scalytics, Inc. - https://www.scalytics.io
SPDX-License-Identifier: Apache-2.0
-->

# Advanced Config

This document lists non-essential tuning variables. Most deployments should
leave these unset and rely on built-in defaults.

## Browser Bridge

| Variable | Default |
|---|---|
| `BROWSER_ENABLED` | `true` (compose) |
| `BROWSER_WS_URL` | `ws://browser:3000` |
| `BROWSER_MAX_CONCURRENCY` | `4` |
| `BROWSER_QUEUE_SIZE` | `20` |
| `BROWSER_CONNECT_RETRIES` | `3` |
| `BROWSER_CONNECT_RETRY_DELAY_MS` | `1000` |
| `BROWSER_TIMEOUT_MS` | `30000` |

## Fetch + Cadence

| Variable | Default |
|---|---|
| `INTERVAL_MS` | `900000` |
| `FETCH_TIMEOUT_FAST_MS` | `3000` |
| `HTTP_TIMEOUT_MS` | `15000` |
| `FETCH_WORKERS` | `12` |
| `MAX_PER_SOURCE` | `40` |
| `RECENT_WINDOW_PER_SOURCE` | `20` |
| `HTML_SCRAPE_INTERVAL_HOURS` | `24` |
| `X_FETCH_PAUSE_MS` | `1250` |

## Alert Lifecycle

| Variable | Default |
|---|---|
| `ALERT_COOLDOWN_HOURS` | `24` |
| `ALERT_STALE_DAYS` | `14` |
| `ALERT_ARCHIVE_DAYS` | `90` |
| `REMOVED_RETENTION_DAYS` | `14` |

## Discovery + Vetting

| Variable | Default |
|---|---|
| `DISCOVER_BACKGROUND` | `true` |
| `STRUCTURED_DISCOVERY_INTERVAL_HOURS` | `168` |
| `DDG_SEARCH_ENABLED` | `true` |
| `DDG_SEARCH_MAX_QUERIES` | `40` |
| `DDG_SEARCH_DELAY_MS` | `5000` |
| `DISCOVER_SOCIAL_ENABLED` | `true` |
| `DISCOVER_SOCIAL_MAX_TARGETS` | `24` |
| `SOURCE_VETTING_REQUIRED` | `true` |
| `SOURCE_MIN_QUALITY` | `0.6` |
| `SOURCE_MIN_OPERATIONAL_RELEVANCE` | `0.6` |

## Noise + Scoring

| Variable | Default |
|---|---|
| `ALARM_RELEVANCE_THRESHOLD` | `0.72` |
| `NOISE_POLICY_PATH` | `registry/noise_policy.json` |
| `NOISE_POLICY_B_PATH` | `registry/noise_policy_b.json` |
| `NOISE_POLICY_B_PERCENT` | `0` |
| `NOISE_METRICS_OUTPUT_PATH` | `public/noise-metrics.json` |

## Zone Briefings + Overlays

| Variable | Default |
|---|---|
| `UCDP_API_VERSION` | `26.0.1` |
| `ZONE_BRIEFING_REFRESH_HOURS` | `24` |
| `ZONE_BRIEFING_ACLED_ENABLED` | `true` |
| `TERROR_ANALYSIS_REFRESH_HOURS` | `24` |
| `TERROR_ANALYSIS_UNCHANGED_HOURS` | `72` |
| `TERROR_ANALYSIS_EVIDENCE_HOURS` | `72` |
| `TERROR_ANALYSIS_MAX_EVIDENCE` | `24` |
| `MILITARY_BASES_ENABLED` | `true` |
| `MILITARY_BASES_REFRESH_HOURS` | `168` |

## OpenAI-Compatible LLM Runtime

All OSINT LLM workloads use the same OpenAI-compatible base URL and API key.
The configured model remains the first choice. When the endpoint supports
`GET /models`, kafSIEM probes it at startup, caches the inventory, selects an
available configured fallback, and refreshes immediately after a model 404.
Gateways without a models endpoint continue using the configured model.

| Variable | Default |
|---|---|
| `LLM_PROVIDER` | `openai-compatible` |
| `LLM_BASE_URL` | `https://api.openai.com/v1` |
| `LLM_API_KEY` | empty |
| `LLM_MODEL` | `gpt-4.1-mini` |
| `LLM_MODEL_FALLBACKS` | empty |
| `ALERT_LLM_MODEL` | `gpt-4.1-mini` |
| `ALERT_LLM_MODEL_FALLBACKS` | empty |
| `LLM_MODEL_DISCOVERY_ENABLED` | `true` |
| `LLM_MODEL_REFRESH_HOURS` | `168` |
| `LLM_MAX_OUTPUT_TOKENS` | `1200` |

Legacy shared endpoint names prefixed with `SOURCE_VETTING_` remain supported
for upgrades. The canonical `LLM_*` value wins when both names are set.

## Kafka Alerts

| Variable | Default |
|---|---|
| `KAFKA_ENABLED` | `false` |
| `KAFKA_GROUP_ID` | `kafsiem-kafka` |
| `KAFKA_CLIENT_ID` | `kafsiem-collector` |
| `KAFKA_SECURITY_PROTOCOL` | `PLAINTEXT` |
| `KAFKA_SASL_MECHANISM` | `PLAIN` |
| `KAFKA_TEST_ON_START` | `true` |
| `KAFKA_MAX_RECORD_BYTES` | `1048576` |
| `KAFKA_MAX_PER_CYCLE` | `500` |
| `KAFKA_POLL_TIMEOUT_MS` | `2000` |
| `KAFKA_MAPPER_PATH` | `registry/kafka_mapper.json` |
| `AGENTOPS_ENABLED` | `false` |
| `AGENTOPS_GROUP_ID` | `kafsiem-agentops` |
| `AGENTOPS_CLIENT_ID` | `kafsiem-agentops` |
| `AGENTOPS_TOPIC_MODE` | `auto` |
| `AGENTOPS_SECURITY_PROTOCOL` | `PLAINTEXT` |
| `AGENTOPS_SASL_MECHANISM` | `PLAIN` |
| `AGENTOPS_POLICY_PATH` | `/config/agentops_policy.yaml` |
| `AGENTOPS_REPLAY_ENABLED` | `true` |
| `AGENTOPS_REPLAY_PREFIX` | `kafsiem-agentops-replay` |
| `AGENTOPS_REJECT_TOPIC` | `group.<group>.agentops.rejects` when `AGENTOPS_GROUP_NAME` is set |
| `AGENTOPS_OUTPUT_PATH` | `public/agentops.db` |
| `UI_MODE` | `OSINT` |
| `PROFILE` | `osint-default` |
| `UI_POLICY_PATH` | `/config/ui_policy.yaml` |

## Infra + Images

| Variable | Default |
|---|---|
| `KAFSIEM_WEB_IMAGE` | `ghcr.io/scalytics/kafsiem-web:latest` |
| `KAFSIEM_COLLECTOR_IMAGE` | `ghcr.io/scalytics/kafsiem-collector:latest` |
| `KAFSIEM_BROWSER_IMAGE` | `ghcr.io/browserless/chromium:v2.44.0` |
| `KAFSIEM_HTTP_PORT` | `8080` (derived by installer) |
| `KAFSIEM_HTTPS_PORT` | `8443` (derived by installer) |
