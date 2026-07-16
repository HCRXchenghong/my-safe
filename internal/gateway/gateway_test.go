package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

type recordingEventSink struct {
	mu     sync.Mutex
	events []domain.Event
}

func (sink *recordingEventSink) Emit(event domain.Event) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.events = append(sink.events, event)
	return nil
}

func (sink *recordingEventSink) snapshot() []domain.Event {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]domain.Event(nil), sink.events...)
}

func TestBlockModeStopsCommonAttacksBeforeUpstream(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamHits.Add(1)
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "upstream")
	}))
	t.Cleanup(upstream.Close)
	gateway, err := New(Config{Mode: ModeBlock, Upstream: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	t.Cleanup(server.Close)

	valid := get(t, server.URL+"/products?id=42")
	if valid.StatusCode != http.StatusOK {
		t.Fatalf("valid request status = %d", valid.StatusCode)
	}
	_ = valid.Body.Close()
	baselineHits := upstreamHits.Load()

	attacks := []struct {
		name string
		path string
	}{
		{"SQL injection", "/search?id=1%27%20OR%20%271%27%3D%271%27--"},
		{"XSS", "/search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E"},
		{"path traversal", "/download?file=..%2F..%2Fetc%2Fpasswd"},
	}
	for _, attack := range attacks {
		attack := attack
		t.Run(attack.name, func(t *testing.T) {
			response := get(t, server.URL+attack.path)
			defer response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				body, _ := io.ReadAll(response.Body)
				t.Fatalf("status = %d, body = %q", response.StatusCode, body)
			}
		})
	}
	if got := upstreamHits.Load(); got != baselineHits {
		t.Fatalf("blocked attacks reached upstream: hits = %d, baseline = %d", got, baselineHits)
	}
}

func TestObserveModeReportsButAllowsAttack(t *testing.T) {
	var logs bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	gateway, err := New(Config{Mode: ModeObserve, Upstream: upstream.URL, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	t.Cleanup(server.Close)

	response := get(t, server.URL+"/search?id=1%27%20OR%20%271%27%3D%271%27--")
	_ = response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("observe status = %d, want upstream 204", response.StatusCode)
	}
	if !strings.Contains(logs.String(), "waf rule matched") {
		t.Fatalf("observe mode did not log a rule match: %s", logs.String())
	}
}

func TestRuleEventsExcludeRequestSecretsAndMatchedData(t *testing.T) {
	secretQuery := "gateway-query-secret-marker"
	secretToken := "gateway-authorization-secret-marker"
	sink := &recordingEventSink{}
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	handler, err := New(Config{Mode: ModeObserve, Upstream: upstream.URL, EventSink: sink})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	request, err := http.NewRequest(http.MethodGet, server.URL+"/search?q=%3Cscript%3E"+secretQuery+"%3C%2Fscript%3E", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+secretToken)
	request.Header.Set("Cookie", "session="+secretToken)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	events := sink.snapshot()
	if len(events) == 0 {
		t.Fatal("WAF match produced no Gateway event")
	}
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secretQuery) || strings.Contains(string(encoded), secretToken) || strings.Contains(string(encoded), "<script>") {
		t.Fatalf("Gateway event leaked request data: %s", encoded)
	}
	for _, event := range events {
		if event.Kind != "gateway.waf.rule_match" || event.Evidence["rule_id"] == nil || event.Evidence["request_data_included"] != false {
			t.Fatalf("Gateway event = %#v", event)
		}
	}
}

func TestBypassModeDoesNotInitializeWAF(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(upstream.Close)
	gateway, err := New(Config{Mode: ModeBypass, Upstream: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/?q=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("bypass status = %d", recorder.Code)
	}
}

func TestGatewayHealthDoesNotReachUpstream(t *testing.T) {
	var upstreamHits atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamHits.Add(1)
	}))
	t.Cleanup(upstream.Close)
	gateway, err := New(Config{Mode: ModeBypass, Upstream: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/__mysafe/healthz", nil)
	recorder := httptest.NewRecorder()
	gateway.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || upstreamHits.Load() != 0 {
		t.Fatalf("health status = %d, upstream hits = %d", recorder.Code, upstreamHits.Load())
	}
}

func TestGatewayReplacesUntrustedForwardingHeaders(t *testing.T) {
	forwarded := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		forwarded <- request.Header.Get("X-Forwarded-For")
		writer.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(upstream.Close)
	gateway, err := New(Config{Mode: ModeBypass, Upstream: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	t.Cleanup(server.Close)
	request, err := http.NewRequest(http.MethodGet, server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Forwarded-For", "203.0.113.99")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	got := <-forwarded
	if strings.Contains(got, "203.0.113.99") || got == "" {
		t.Fatalf("trusted forwarding chain = %q", got)
	}
}

func get(t *testing.T, url string) *http.Response {
	t.Helper()
	response, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	return response
}
