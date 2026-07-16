package control

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/security"
	"github.com/HCRXchenghong/my-safe/internal/store"
)

const (
	testBootstrapToken = "bootstrap-token-at-least-32-bytes"
	testAdminToken     = "admin-token-at-least-32-bytes-long"
)

func TestServerAgentLifecycleAndRedaction(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	memory := store.NewMemory()
	handler, err := New(Config{
		Store:          memory,
		BootstrapToken: testBootstrapToken,
		AdminToken:     testAdminToken,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	unauthorized := doJSON(t, http.MethodGet, server.URL+"/v1/agents", "", nil)
	if unauthorized.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.StatusCode)
	}
	_ = unauthorized.Body.Close()

	registration := doJSON(t, http.MethodPost, server.URL+"/v1/agents/register", testBootstrapToken, map[string]any{
		"machine_id":   "machine-1",
		"hostname":     "server-1",
		"version":      "0.1.0",
		"platform":     "linux",
		"architecture": "amd64",
	})
	if registration.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(registration.Body)
		t.Fatalf("registration status = %d, body = %s", registration.StatusCode, body)
	}
	var credentials registrationResponse
	decodeResponse(t, registration, &credentials)
	if credentials.AgentID == "" || credentials.Credential == "" {
		t.Fatalf("registration response = %#v", credentials)
	}

	heartbeat := doJSON(t, http.MethodPost, server.URL+"/v1/agents/"+credentials.AgentID+"/heartbeat", credentials.Credential, map[string]any{
		"agent_version": "0.1.1",
		"queue_depth":   1,
	})
	if heartbeat.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat status = %d", heartbeat.StatusCode)
	}
	_ = heartbeat.Body.Close()

	event := domain.Event{
		ID:         "evt-1",
		Kind:       "host.scan",
		Severity:   domain.SeverityHigh,
		Summary:    "host scan found a risky setting",
		OccurredAt: now,
		Evidence: map[string]any{
			"path":          "/etc/ssh/sshd_config",
			"authorization": "must-not-be-stored",
		},
	}
	batch := map[string]any{"events": []domain.Event{event}}
	firstBatch := doJSON(t, http.MethodPost, server.URL+"/v1/agents/"+credentials.AgentID+"/events", credentials.Credential, batch)
	if firstBatch.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(firstBatch.Body)
		t.Fatalf("first event batch status = %d, body = %s", firstBatch.StatusCode, body)
	}
	var firstResult map[string]int
	decodeResponse(t, firstBatch, &firstResult)
	if firstResult["accepted"] != 1 {
		t.Fatalf("first event result = %#v", firstResult)
	}
	duplicateBatch := doJSON(t, http.MethodPost, server.URL+"/v1/agents/"+credentials.AgentID+"/events", credentials.Credential, batch)
	var duplicateResult map[string]int
	decodeResponse(t, duplicateBatch, &duplicateResult)
	if duplicateResult["duplicates"] != 1 {
		t.Fatalf("duplicate event result = %#v", duplicateResult)
	}

	alertsResponse := doJSON(t, http.MethodGet, server.URL+"/v1/alerts?severity=high", testAdminToken, nil)
	if alertsResponse.StatusCode != http.StatusOK {
		t.Fatalf("alerts status = %d", alertsResponse.StatusCode)
	}
	var alertsPayload struct {
		Alerts []domain.Event `json:"alerts"`
	}
	decodeResponse(t, alertsResponse, &alertsPayload)
	if len(alertsPayload.Alerts) != 1 {
		t.Fatalf("alerts = %#v", alertsPayload.Alerts)
	}
	if got := alertsPayload.Alerts[0].Evidence["authorization"]; got != security.Redacted {
		t.Fatalf("authorization evidence = %v, want redacted", got)
	}
	if alertsPayload.Alerts[0].AgentID != credentials.AgentID {
		t.Fatal("control plane did not bind event to authenticated agent")
	}

	storedAgent, err := memory.AgentByID(context.Background(), credentials.AgentID)
	if err != nil || storedAgent.Version != "0.1.1" || !storedAgent.LastSeenAt.Equal(now) {
		t.Fatalf("stored agent = %#v, %v", storedAgent, err)
	}
}

func TestServerRejectsUnknownJSONFields(t *testing.T) {
	t.Parallel()
	handler, err := New(Config{
		Store:          store.NewMemory(),
		BootstrapToken: testBootstrapToken,
		AdminToken:     testAdminToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/agents/register", bytes.NewBufferString(`{"machine_id":"x","unknown":true}`))
	request.Header.Set("Authorization", "Bearer "+testBootstrapToken)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
}

func TestPolicyOptimisticConcurrencyAndAudit(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 17, 0, 0, 0, time.UTC)
	handler, err := New(Config{
		Store: store.NewMemory(), BootstrapToken: testBootstrapToken, AdminToken: testAdminToken,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	registration := doJSON(t, http.MethodPost, server.URL+"/v1/agents/register", testBootstrapToken, map[string]any{
		"machine_id": "policy-machine", "hostname": "policy-host", "version": "test",
		"platform": "linux", "architecture": "amd64",
	})
	var credentials registrationResponse
	decodeResponse(t, registration, &credentials)
	payload := map[string]any{
		"expected_revision": 0, "file_integrity_enabled": true,
		"file_watch_paths": []string{"/var/www", "/etc/nginx"},
		"ssh_auth_enabled": true, "ssh_threshold": 5, "ssh_window_seconds": 300,
		"runtime_watch_enabled": true,
	}
	created := doJSON(t, http.MethodPut, server.URL+"/v1/agents/"+credentials.AgentID+"/policy", testAdminToken, payload)
	if created.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(created.Body)
		t.Fatalf("policy status = %d, body=%s", created.StatusCode, body)
	}
	var policy domain.Policy
	decodeResponse(t, created, &policy)
	if policy.Revision != 1 || len(policy.FileWatchPaths) != 2 || policy.FileWatchPaths[0] != "/etc/nginx" {
		t.Fatalf("policy = %#v", policy)
	}
	stale := doJSON(t, http.MethodPut, server.URL+"/v1/agents/"+credentials.AgentID+"/policy", testAdminToken, payload)
	if stale.StatusCode != http.StatusConflict {
		t.Fatalf("stale policy status = %d", stale.StatusCode)
	}
	_ = stale.Body.Close()
	fetched := doJSON(t, http.MethodGet, server.URL+"/v1/agents/"+credentials.AgentID+"/policy", credentials.Credential, nil)
	if fetched.StatusCode != http.StatusOK {
		t.Fatalf("Agent policy fetch status = %d", fetched.StatusCode)
	}
	var fetchedPolicy domain.Policy
	decodeResponse(t, fetched, &fetchedPolicy)
	if fetchedPolicy.ID != policy.ID || fetchedPolicy.Revision != 1 {
		t.Fatalf("fetched policy = %#v", fetchedPolicy)
	}
	audits := doJSON(t, http.MethodGet, server.URL+"/v1/audit-logs", testAdminToken, nil)
	var auditPayload struct {
		AuditLogs []domain.AuditLog `json:"audit_logs"`
	}
	decodeResponse(t, audits, &auditPayload)
	if len(auditPayload.AuditLogs) != 1 || auditPayload.AuditLogs[0].Action != "agent.policy.updated" || auditPayload.AuditLogs[0].Resource == "" {
		t.Fatalf("audit logs = %#v", auditPayload.AuditLogs)
	}
}

func doJSON(t *testing.T, method, url, token string, payload any) *http.Response {
	t.Helper()
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func decodeResponse(t *testing.T, response *http.Response, target any) {
	t.Helper()
	defer response.Body.Close()
	if err := json.NewDecoder(response.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}
