//go:build linux

package integration_test

import (
	"context"
	"encoding/json"
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
	"github.com/HCRXchenghong/my-safe/internal/gateway"
	"github.com/HCRXchenghong/my-safe/internal/gatewayevents"
	"github.com/HCRXchenghong/my-safe/internal/store"
)

func TestGatewayOfflineOutboxReachesAgentAndControlPlane(t *testing.T) {
	now := time.Now().UTC()
	memory := store.NewMemory()
	controlHandler, err := control.New(control.Config{
		Store: memory, BootstrapToken: bootstrapToken, AdminToken: adminToken,
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	controlServer := httptest.NewServer(controlHandler)
	t.Cleanup(controlServer.Close)
	socketDirectory, err := os.MkdirTemp("", "mysafe-feed-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDirectory) })
	socketPath := filepath.Join(socketDirectory, "events.sock")
	outbox, err := gatewayevents.New(gatewayevents.Config{StateDir: t.TempDir(), SocketPath: socketPath, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	gatewayHandler, err := gateway.New(gateway.Config{Mode: gateway.ModeObserve, Upstream: upstream.URL, EventSink: outbox, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	gatewayServer := httptest.NewServer(gatewayHandler)
	t.Cleanup(gatewayServer.Close)

	secret := "offline-gateway-query-must-not-leak"
	response, err := http.Get(gatewayServer.URL + "/search?id=1%27%20OR%20%271%27%3D%271%27--" + secret)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	agentErrors := make(chan error, 1)
	go func() {
		agentErrors <- agent.Run(ctx, agent.Config{
			StateDir: t.TempDir(), ControlURL: controlServer.URL, BootstrapToken: bootstrapToken,
			HTTPClient: controlServer.Client(), Interval: 10 * time.Second,
			DisableFileIntegrity: true, DisableSSHAuth: true, DisableRuntimeWatch: true,
			GatewayEventSocket: socketPath,
		})
	}()
	outboxErrors := make(chan error, 1)
	go func() { outboxErrors <- outbox.Run(ctx, 20*time.Millisecond) }()

	deadline := time.Now().Add(8 * time.Second)
	var gatewayEvent *domain.Event
	for time.Now().Before(deadline) {
		alerts, err := memory.ListAlerts(context.Background(), domain.AlertFilter{Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		for index := range alerts {
			if alerts[index].Kind == "gateway.waf.rule_match" {
				gatewayEvent = &alerts[index]
				break
			}
		}
		if gatewayEvent != nil {
			break
		}
		select {
		case err := <-agentErrors:
			t.Fatalf("Agent stopped before delivery: %v", err)
		case err := <-outboxErrors:
			t.Fatalf("Gateway outbox stopped before delivery: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if gatewayEvent == nil {
		t.Fatal("Gateway event did not reach the control plane")
	}
	encoded, err := json.Marshal(gatewayEvent)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) || gatewayEvent.Evidence["rule_id"] == nil {
		t.Fatalf("Gateway event is unsafe or incomplete: %s", encoded)
	}
	cancel()
	select {
	case err := <-agentErrors:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Agent did not stop")
	}
}
