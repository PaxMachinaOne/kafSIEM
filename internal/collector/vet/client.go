// Copyright 2024 ff, Scalytics, Inc. - https://www.scalytics.io
// SPDX-License-Identifier: Apache-2.0

package vet

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/scalytics/kafSIEM/internal/collector/config"
)

// ErrCircuitOpen is returned without contacting the endpoint after repeated
// consecutive failures. Callers should treat it as "LLM unavailable" and skip
// per-item logging; the failures that tripped the breaker were already logged.
var ErrCircuitOpen = errors.New("llm endpoint circuit open")

const (
	breakerFailureThreshold = 3
	breakerCooldown         = 10 * time.Minute
)

// Breaker state is shared per completions URL, not per Client: clients are
// constructed at many call sites, so instance state would reset constantly.
type breaker struct {
	mu        sync.Mutex
	failures  int
	openUntil time.Time
}

var (
	breakersMu sync.Mutex
	breakers   = map[string]*breaker{}
)

func breakerFor(url string) *breaker {
	breakersMu.Lock()
	defer breakersMu.Unlock()
	b, ok := breakers[url]
	if !ok {
		b = &breaker{}
		breakers[url] = b
	}
	return b
}

func (b *breaker) open() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return time.Now().Before(b.openUntil)
}

func (b *breaker) recordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures++
	if b.failures >= breakerFailureThreshold {
		b.openUntil = time.Now().Add(breakerCooldown)
		b.failures = 0
	}
}

func (b *breaker) recordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.openUntil = time.Time{}
}

type Client struct {
	httpClient  *http.Client
	baseURL     string
	apiKey      string
	model       string
	provider    string
	temperature float64
	breaker     *breaker
}

func NewClient(cfg config.Config) *Client {
	timeout := time.Duration(cfg.VettingTimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 45 * time.Second
	}
	baseURL := strings.TrimSpace(cfg.VettingBaseURL)
	return &Client{
		httpClient:  &http.Client{Timeout: timeout},
		baseURL:     baseURL,
		apiKey:      strings.TrimSpace(cfg.VettingAPIKey),
		model:       strings.TrimSpace(cfg.VettingModel),
		provider:    strings.TrimSpace(cfg.VettingProvider),
		temperature: cfg.VettingTemperature,
		breaker:     breakerFor(completionsURL(baseURL)),
	}
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float64   `json:"temperature,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func (c *Client) Complete(ctx context.Context, messages []Message) (string, error) {
	if c.breaker.open() {
		return "", ErrCircuitOpen
	}
	reqBody, err := json.Marshal(chatRequest{
		Model:       c.model,
		Messages:    messages,
		Temperature: c.temperature,
	})
	if err != nil {
		return "", fmt.Errorf("marshal source vetting request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, completionsURL(c.baseURL), bytes.NewReader(reqBody))
	if err != nil {
		return "", fmt.Errorf("build source vetting request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	if c.provider != "" {
		req.Header.Set("X-KAFSIEM-Provider", c.provider)
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		// A caller-cancelled context is not an endpoint failure.
		if ctx.Err() != context.Canceled {
			c.breaker.recordFailure()
		}
		return "", fmt.Errorf("request source vetting completion: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		c.breaker.recordFailure()
		return "", fmt.Errorf("read source vetting response: %w", err)
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		c.breaker.recordFailure()
		return "", fmt.Errorf("source vetting endpoint status %d: %s", res.StatusCode, strings.TrimSpace(string(body)))
	}
	c.breaker.recordSuccess()

	var parsed chatResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("decode source vetting response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("source vetting response returned no choices")
	}
	return strings.TrimSpace(parsed.Choices[0].Message.Content), nil
}

func completionsURL(baseURL string) string {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return "https://api.openai.com/v1/chat/completions"
	}
	if strings.HasSuffix(baseURL, "/chat/completions") {
		return baseURL
	}
	return baseURL + "/chat/completions"
}
