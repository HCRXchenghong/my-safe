package integration_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/agent"
	"github.com/HCRXchenghong/my-safe/internal/control"
	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/store"
)

const (
	bootstrapToken = "integration-bootstrap-token-32-bytes"
	adminToken     = "integration-admin-token-32-bytes-long"
)

func TestAgentControlPlaneEndToEnd(t *testing.T) {
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	memory := store.NewMemory()
	handler, err := control.New(control.Config{
		Store:          memory,
		BootstrapToken: bootstrapToken,
		AdminToken:     adminToken,
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	stateDir := t.TempDir()

	config := agent.Config{
		StateDir:             stateDir,
		ControlURL:           server.URL,
		BootstrapToken:       bootstrapToken,
		HTTPClient:           server.Client(),
		Now:                  func() time.Time { return now },
		DisableFileIntegrity: true,
		DisableSSHAuth:       true,
		DisableRuntimeWatch:  true,
	}
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatalf("first RunOnce() error = %v", err)
	}
	queue, err := agent.OpenEncryptedQueue(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	queueDepth, err := queue.Len()
	if err != nil || queueDepth != 0 {
		t.Fatalf("queue depth after successful delivery = %d, %v", queueDepth, err)
	}

	// Registration credentials persist, so later runs do not need the bootstrap token.
	now = now.Add(time.Minute)
	config.BootstrapToken = ""
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatalf("second RunOnce() error = %v", err)
	}

	agents, err := memory.ListAgents(context.Background(), 10)
	if err != nil || len(agents) != 1 {
		t.Fatalf("agents = %#v, %v", agents, err)
	}
	if agents[0].CredentialHash != nil {
		t.Fatal("agent listing exposed a credential hash")
	}
	alerts := fetchAlerts(t, server.URL, server.Client())
	if len(alerts) != 2 {
		t.Fatalf("alerts = %#v, want two delivered scan events", alerts)
	}
	for _, alert := range alerts {
		if alert.AgentID != agents[0].ID || alert.Kind != "host.inventory" {
			t.Fatalf("alert is not connected to registered agent: %#v", alert)
		}
	}
}

func TestAgentRetainsEncryptedQueueWhenControlPlaneIsOffline(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()
	stateDir := t.TempDir()
	err := agent.RunOnce(context.Background(), agent.Config{
		StateDir:             stateDir,
		ControlURL:           url,
		BootstrapToken:       bootstrapToken,
		HTTPClient:           &http.Client{Timeout: time.Second},
		DisableFileIntegrity: true,
		DisableSSHAuth:       true,
		DisableRuntimeWatch:  true,
	})
	if err == nil {
		t.Fatal("RunOnce() succeeded with an offline control plane")
	}
	queue, openErr := agent.OpenEncryptedQueue(stateDir)
	if openErr != nil {
		t.Fatal(openErr)
	}
	depth, lenErr := queue.Len()
	if lenErr != nil || depth != 1 {
		t.Fatalf("offline queue depth = %d, %v; want 1", depth, lenErr)
	}
}

func TestFileIntegrityChangeTravelsThroughEncryptedAgentQueueToControlPlane(t *testing.T) {
	now := time.Date(2026, 7, 16, 11, 0, 0, 0, time.UTC)
	memory := store.NewMemory()
	handler, err := control.New(control.Config{
		Store: memory, BootstrapToken: bootstrapToken, AdminToken: adminToken,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	watchDir := t.TempDir()
	protectedPath := filepath.Join(watchDir, "service.conf")
	if err := os.WriteFile(protectedPath, []byte("safe=true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := agent.Config{
		StateDir: stateDir, ControlURL: server.URL, BootstrapToken: bootstrapToken,
		HTTPClient: server.Client(), Now: func() time.Time { return now },
		FileWatchPaths:      []string{watchDir},
		DisableSSHAuth:      true,
		DisableRuntimeWatch: true,
	}
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	secret := "changed-file-body-must-never-leave-agent"
	if err := os.WriteFile(protectedPath, []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	config.BootstrapToken = ""
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	alerts := fetchAlerts(t, server.URL, server.Client())
	var integrityEvent *domain.Event
	for index := range alerts {
		if alerts[index].Kind == "file.integrity.changed" {
			integrityEvent = &alerts[index]
			break
		}
	}
	if integrityEvent == nil || integrityEvent.Evidence["change"] != "content_changed" {
		t.Fatalf("integrity event not delivered: %#v", alerts)
	}
	encoded, err := json.Marshal(integrityEvent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("file body leaked through the control-plane event")
	}
	queue, err := agent.OpenEncryptedQueue(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	depth, err := queue.Len()
	if err != nil || depth != 0 {
		t.Fatalf("queue depth = %d, %v", depth, err)
	}
}

func TestSSHBruteForceTravelsThroughEncryptedAgentQueueToControlPlane(t *testing.T) {
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	memory := store.NewMemory()
	handler, err := control.New(control.Config{
		Store: memory, BootstrapToken: bootstrapToken, AdminToken: adminToken,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	logPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	config := agent.Config{
		StateDir: stateDir, ControlURL: server.URL, BootstrapToken: bootstrapToken,
		HTTPClient: server.Client(), Now: func() time.Time { return now },
		DisableFileIntegrity: true, SSHAuthLogPaths: []string{logPath}, DisableRuntimeWatch: true,
	}
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	rawMarker := "raw-ssh-log-marker-must-not-leak"
	lines := ""
	for port := 40001; port <= 40005; port++ {
		lines += fmt.Sprintf("host sshd[1]: Failed password for invalid user %s from 198.51.100.77 port %d ssh2\n", rawMarker, port)
	}
	if err := os.WriteFile(logPath, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	config.BootstrapToken = ""
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	alerts := fetchAlerts(t, server.URL, server.Client())
	var brute *domain.Event
	for index := range alerts {
		if alerts[index].Kind == "ssh.auth.bruteforce" {
			brute = &alerts[index]
			break
		}
	}
	if brute == nil || brute.Evidence["source_ip"] != "198.51.100.77" {
		t.Fatalf("SSH brute-force event not delivered: %#v", alerts)
	}
	encoded, err := json.Marshal(brute)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "sshd[1]") || strings.Contains(string(encoded), "port 40005") {
		t.Fatal("raw SSH log line leaked through the control plane")
	}
}

func TestRuntimePortChangeTravelsThroughEncryptedAgentQueueToControlPlane(t *testing.T) {
	now := time.Date(2026, 7, 16, 15, 0, 0, 0, time.UTC)
	memory := store.NewMemory()
	handler, err := control.New(control.Config{
		Store: memory, BootstrapToken: bootstrapToken, AdminToken: adminToken,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	procRoot := t.TempDir()
	netDir := filepath.Join(procRoot, "net")
	if err := os.MkdirAll(netDir, 0o700); err != nil {
		t.Fatal(err)
	}
	header := "sl local_address rem_address st\n"
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(header+"0: 0100007F:0016 00000000:0000 0A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "tcp6"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	pidDir := filepath.Join(procRoot, "100")
	if err := os.MkdirAll(pidDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\tinit\nUid:\t0\t0\t0\t0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := agent.Config{
		StateDir: t.TempDir(), ControlURL: server.URL, BootstrapToken: bootstrapToken,
		HTTPClient: server.Client(), Now: func() time.Time { return now },
		DisableFileIntegrity: true, DisableSSHAuth: true, ProcRoot: procRoot,
	}
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(netDir, "tcp"), []byte(header+"0: 00000000:1F90 00000000:0000 0A\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	config.BootstrapToken = ""
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	alerts := fetchAlerts(t, server.URL, server.Client())
	found := false
	for _, event := range alerts {
		if event.Kind == "runtime.port.opened" && event.Evidence["port"] == float64(8080) && event.Evidence["scope"] == "wildcard" {
			found = true
		}
	}
	if !found {
		t.Fatalf("runtime port event not delivered: %#v", alerts)
	}
}

func TestAgentFetchesAndPersistsMonotonicPolicy(t *testing.T) {
	now := time.Date(2026, 7, 16, 18, 0, 0, 0, time.UTC)
	memory := store.NewMemory()
	handler, err := control.New(control.Config{
		Store: memory, BootstrapToken: bootstrapToken, AdminToken: adminToken,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	config := agent.Config{
		StateDir: stateDir, ControlURL: server.URL, BootstrapToken: bootstrapToken,
		HTTPClient: server.Client(), Now: func() time.Time { return now },
		DisableFileIntegrity: true, DisableSSHAuth: true, DisableRuntimeWatch: true,
	}
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	identity, err := agent.LoadIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	policy := domain.Policy{
		ID: "pol_integration", AgentID: identity.AgentID, Revision: 1,
		FileIntegrityEnabled: true, FileWatchPaths: []string{"/srv/app"},
		SSHAuthEnabled: true, SSHThreshold: 6, SSHWindowSeconds: 300,
		RuntimeWatchEnabled: true, UpdatedAt: now,
	}
	audit := domain.AuditLog{
		ID: "aud_integration", Actor: "test", Action: "agent.policy.updated",
		Resource: "agent/" + identity.AgentID + "/policy", OccurredAt: now,
	}
	if err := memory.SavePolicyAndAudit(context.Background(), policy, 0, audit); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	config.BootstrapToken = ""
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	stored, exists, err := agent.LoadPolicy(stateDir, identity.AgentID)
	if err != nil || !exists || stored.Revision != 1 || stored.SSHThreshold != 6 {
		t.Fatalf("persisted policy = %#v, %t, %v", stored, exists, err)
	}
}

func fetchAlerts(t *testing.T, baseURL string, client *http.Client) []domain.Event {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, baseURL+"/v1/alerts", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("alerts status = %d, body = %s", response.StatusCode, body)
	}
	var payload struct {
		Alerts []domain.Event `json:"alerts"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	return payload.Alerts
}
