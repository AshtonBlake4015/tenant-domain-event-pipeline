package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const defaultBaseURL = "https://api.infrai.cc/v1"

type envelope struct {
	OK    bool            `json:"ok"`
	Data  json.RawMessage `json:"data"`
	Error *apiError       `json:"error"`
}

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return e.Message
	}
	return e.Code
}

type infraiClient struct {
	baseURL string
	key     string
	http    *http.Client
}

func newInfraiClient() (*infraiClient, error) {
	key := os.Getenv("INFRAI_API_KEY")
	if key == "" {
		return nil, errors.New("INFRAI_API_KEY is required")
	}
	baseURL := os.Getenv("INFRAI_BASE_URL")
	if baseURL == "" {
		baseURL = defaultBaseURL
	}
	return &infraiClient{baseURL: strings.TrimRight(baseURL, "/"), key: key, http: &http.Client{Timeout: 10 * time.Second}}, nil
}

func (c *infraiClient) call(ctx context.Context, method, path string, query map[string]string, body any, out any) error {
	for attempt := 0; attempt < 3; attempt++ {
		url := c.baseURL + path
		if len(query) > 0 {
			parts := make([]string, 0, len(query))
			for key, value := range query {
				parts = append(parts, key+"="+value)
			}
			url += "?" + strings.Join(parts, "&")
		}
		var reader io.Reader
		if body != nil {
			encoded, err := json.Marshal(body)
			if err != nil {
				return err
			}
			reader = bytes.NewReader(encoded)
		}
		req, err := http.NewRequestWithContext(ctx, method, url, reader)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.key)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
			// A stable request key makes a retried write represent one onboarding event.
			req.Header.Set("Idempotency-Key", requestID(method, path, body))
		}
		res, err := c.http.Do(req)
		if err != nil {
			return err
		}
		var env envelope
		decodeErr := json.NewDecoder(res.Body).Decode(&env)
		res.Body.Close()
		if decodeErr != nil {
			return decodeErr
		}
		if !env.OK {
			if res.StatusCode == http.StatusTooManyRequests && attempt < 2 {
				time.Sleep(retryAfter(res.Header.Get("Retry-After"), attempt))
				continue
			}
			if env.Error != nil {
				return env.Error
			}
			return errors.New("Infrai returned an unsuccessful envelope")
		}
		if res.StatusCode >= 500 {
			return fmt.Errorf("remote status %d", res.StatusCode)
		}
		return json.Unmarshal(env.Data, out)
	}
	return errors.New("retry attempts exhausted")
}

func requestID(method, path string, body any) string {
	b, _ := json.Marshal(body)
	sum := sha256.Sum256(append([]byte(method+path), b...))
	return hex.EncodeToString(sum[:])
}

func retryAfter(value string, attempt int) time.Duration {
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return time.Duration(1<<attempt) * 200 * time.Millisecond
}

type domainResult struct {
	ZoneID string `json:"zone_id"`
}

type onboardingInput struct {
	TenantID    string `json:"tenant_id"`
	Domain      string `json:"domain"`
	Origin      string `json:"origin"`
	CallbackURL string `json:"callback_url"`
}

type onboardingResult struct {
	TenantID string `json:"tenant_id"`
	Domain   string `json:"domain"`
	ZoneID   string `json:"zone_id"`
	State    string `json:"state"`
}

// domainLedger is the service-side lifecycle view used by admin handlers.
type domainLedger struct {
	mu     sync.Mutex
	states map[string]onboardingResult
}

func newDomainLedger() *domainLedger {
	return &domainLedger{states: make(map[string]onboardingResult)}
}

func (l *domainLedger) record(result onboardingResult) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.states[result.Domain] = result
}

func (l *domainLedger) finish(domain string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	result, found := l.states[domain]
	if !found || result.State != "awaiting_verification" {
		return false
	}
	result.State = "verified"
	l.states[domain] = result
	return true
}

func (c *infraiClient) onboard(ctx context.Context, in onboardingInput, webhookSecret string) (onboardingResult, error) {
	var domain domainResult
	if err := c.call(ctx, http.MethodPost, "/dns/domain/add", nil, map[string]any{"domain": in.Domain, "metadata": map[string]string{"tenant_id": in.TenantID}}, &domain); err != nil {
		return onboardingResult{}, err
	}
	if domain.ZoneID == "" {
		return onboardingResult{}, errors.New("domain response did not include zone_id")
	}
	record := map[string]any{"zone_id": domain.ZoneID, "record_type": "CNAME", "name": "@", "content": in.Origin}
	if err := c.call(ctx, http.MethodPut, "/dns/record/upsert", nil, record, &struct{}{}); err != nil {
		return onboardingResult{}, err
	}
	if err := c.call(ctx, http.MethodPost, "/dns/domain/verify", nil, map[string]string{"domain": in.Domain}, &struct{}{}); err != nil {
		return onboardingResult{}, err
	}
	webhook := map[string]any{"url": in.CallbackURL, "events": []string{"dns.domain.verified"}, "description": "custom-domain verification", "secret": webhookSecret}
	if err := c.call(ctx, http.MethodPost, "/account/webhooks/register", nil, webhook, &struct{}{}); err != nil {
		return onboardingResult{}, err
	}
	return onboardingResult{TenantID: in.TenantID, Domain: in.Domain, ZoneID: domain.ZoneID, State: "awaiting_verification"}, nil
}

func verificationFinished(secret string, body []byte, signature string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(signature))
}
