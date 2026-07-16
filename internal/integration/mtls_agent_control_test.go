package integration_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/agent"
	"github.com/HCRXchenghong/my-safe/internal/control"
	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/mtls"
	"github.com/HCRXchenghong/my-safe/internal/store"
)

func TestAgentEnrollsCertificateAndControlRequiresMatchingMTLS(t *testing.T) {
	now := time.Now().UTC()
	issuer, err := mtls.LoadOrCreateIssuer(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	memory := store.NewMemory()
	handler, err := control.New(control.Config{
		Store: memory, BootstrapToken: bootstrapToken, AdminToken: adminToken,
		AgentIssuer: issuer, RequireAgentMTLS: true, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.VerifyClientCertIfGiven,
		ClientCAs:  issuer.CertPool(),
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	stateDir := t.TempDir()
	config := agent.Config{
		StateDir: stateDir, ControlURL: server.URL, BootstrapToken: bootstrapToken,
		HTTPClient: server.Client(), Now: func() time.Time { return now },
		DisableFileIntegrity: true, DisableSSHAuth: true, DisableRuntimeWatch: true,
		CertificateRenewalWindow: 30 * 24 * time.Hour,
	}
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatalf("mTLS enrollment cycle: %v", err)
	}
	identity, err := agent.LoadIdentity(stateDir)
	if err != nil {
		t.Fatal(err)
	}
	certificate, exists, err := mtls.LoadClientCertificate(stateDir, now)
	if err != nil || !exists || !mtls.MatchesAgent(certificate.Leaf, identity.AgentID) {
		t.Fatalf("Agent certificate = %#v, %t, %v", certificate.Leaf, exists, err)
	}
	firstExpiry := certificate.Leaf.NotAfter

	// A stolen bearer token alone is insufficient once mTLS is required.
	request, err := http.NewRequest(http.MethodPost, server.URL+"/v1/agents/"+identity.AgentID+"/heartbeat", bytes.NewBufferString(`{"agent_version":"test","queue_depth":0}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+identity.Credential)
	request.Header.Set("Content-Type", "application/json")
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("token-only heartbeat status = %d", response.StatusCode)
	}

	now = now.Add(time.Minute)
	config.BootstrapToken = ""
	if err := agent.RunOnce(context.Background(), config); err != nil {
		t.Fatalf("mTLS restart cycle: %v", err)
	}
	renewed, exists, err := mtls.LoadClientCertificate(stateDir, now)
	if err != nil || !exists || !renewed.Leaf.NotAfter.After(firstExpiry) {
		t.Fatalf("Agent certificate was not renewed: first=%s renewed=%v exists=%t err=%v", firstExpiry, renewed.Leaf, exists, err)
	}
	alerts, err := memory.ListAlerts(context.Background(), domain.AlertFilter{Limit: 10})
	if err != nil || len(alerts) != 2 {
		t.Fatalf("mTLS delivered alerts = %#v, %v", alerts, err)
	}
}
