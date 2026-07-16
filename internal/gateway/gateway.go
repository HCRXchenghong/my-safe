package gateway

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/id"
	coreruleset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	corazahttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

type Mode string

const (
	ModeBypass  Mode = "bypass"
	ModeObserve Mode = "observe"
	ModeBlock   Mode = "block"
)

func (mode Mode) Valid() bool {
	switch mode {
	case ModeBypass, ModeObserve, ModeBlock:
		return true
	default:
		return false
	}
}

type FailurePolicy string

const (
	FailOpen   FailurePolicy = "fail_open"
	FailClosed FailurePolicy = "fail_closed"
)

func (policy FailurePolicy) Valid() bool {
	return policy == FailOpen || policy == FailClosed
}

type Config struct {
	Mode                    Mode
	FailurePolicy           FailurePolicy
	Upstream                string
	RequestBodyLimitBytes   int
	RequestMemoryLimitBytes int
	Logger                  *slog.Logger
	Transport               http.RoundTripper
	EventSink               EventSink
	Now                     func() time.Time
}

type EventSink interface {
	Emit(domain.Event) error
}

type Gateway struct {
	mode    Mode
	logger  *slog.Logger
	handler http.Handler
}

func New(config Config) (*Gateway, error) {
	if !config.Mode.Valid() {
		return nil, fmt.Errorf("invalid gateway mode %q", config.Mode)
	}
	if config.FailurePolicy == "" {
		config.FailurePolicy = FailOpen
	}
	if !config.FailurePolicy.Valid() {
		return nil, fmt.Errorf("invalid gateway failure policy %q", config.FailurePolicy)
	}
	upstream, err := parseUpstream(config.Upstream)
	if err != nil {
		return nil, err
	}
	if config.RequestBodyLimitBytes == 0 {
		config.RequestBodyLimitBytes = 1 << 20
	}
	if config.RequestMemoryLimitBytes == 0 {
		config.RequestMemoryLimitBytes = 256 << 10
	}
	if config.RequestBodyLimitBytes < 1024 || config.RequestBodyLimitBytes > 64<<20 {
		return nil, errors.New("request body limit must be between 1 KiB and 64 MiB")
	}
	if config.RequestMemoryLimitBytes < 1024 || config.RequestMemoryLimitBytes > config.RequestBodyLimitBytes {
		return nil, errors.New("request memory limit must be between 1 KiB and the request body limit")
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if config.Now == nil {
		config.Now = time.Now
	}

	proxy := httputil.NewSingleHostReverseProxy(upstream)
	proxy.Director = nil
	proxy.Rewrite = func(request *httputil.ProxyRequest) {
		request.SetURL(upstream)
		// SetXForwarded discards client-provided forwarding headers before
		// deriving a new chain from the socket peer.
		request.SetXForwarded()
	}
	if config.Transport != nil {
		proxy.Transport = config.Transport
	} else {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.ResponseHeaderTimeout = 30 * time.Second
		transport.MaxIdleConns = 200
		transport.MaxIdleConnsPerHost = 100
		proxy.Transport = transport
	}
	proxy.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
		config.Logger.Error("gateway upstream failed", "method", request.Method, "error", proxyErr)
		http.Error(writer, "upstream unavailable", http.StatusBadGateway)
	}

	protected := http.Handler(proxy)
	if config.Mode != ModeBypass {
		waf, err := newWAF(config)
		if err != nil {
			return nil, err
		}
		wafHandler := corazahttp.WrapHandler(waf, proxy)
		protected = http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			tracked := &responseStatus{ResponseWriter: writer}
			wafHandler.ServeHTTP(tracked, request)
			if tracked.status != 0 {
				return
			}
			config.Logger.Error("waf request processing failed", "method", request.Method, "failure_policy", config.FailurePolicy)
			if config.FailurePolicy == FailOpen {
				proxy.ServeHTTP(writer, request)
				return
			}
			http.Error(writer, "gateway inspection unavailable", http.StatusServiceUnavailable)
		})
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /__mysafe/healthz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(writer, "{\"status\":\"ok\"}\n")
	})
	mux.Handle("/", protected)
	return &Gateway{
		mode:    config.Mode,
		logger:  config.Logger,
		handler: requestLog(config.Logger, config.Mode, mux),
	}, nil
}

func (gateway *Gateway) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	gateway.handler.ServeHTTP(writer, request)
}

func newWAF(config Config) (coraza.WAF, error) {
	engineMode := "On"
	if config.Mode == ModeObserve {
		engineMode = "DetectionOnly"
	}
	directives := strings.Builder{}
	_, _ = fmt.Fprintf(&directives, `
Include @coraza.conf-recommended
SecRuleEngine %s
SecRequestBodyAccess On
SecRequestBodyLimit %d
SecRequestBodyNoFilesLimit %d
SecRequestBodyInMemoryLimit %d
SecRequestBodyLimitAction Reject
SecResponseBodyAccess Off
Include @crs-setup.conf.example
`, engineMode, config.RequestBodyLimitBytes, config.RequestMemoryLimitBytes, config.RequestMemoryLimitBytes)
	// Coraza's glob expansion uses OS path separators. Enumerating the embedded
	// FS ourselves keeps paths portable on Windows and Linux while preserving
	// the CRS-defined lexical load order.
	rulePaths, err := fs.Glob(coreruleset.FS, "@owasp_crs/*.conf")
	if err != nil {
		return nil, fmt.Errorf("enumerate embedded OWASP CRS rules: %w", err)
	}
	if len(rulePaths) == 0 {
		return nil, errors.New("embedded OWASP CRS contains no rule files")
	}
	for _, rulePath := range rulePaths {
		_, _ = fmt.Fprintf(&directives, "Include %s\n", rulePath)
	}
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(portableRuleFS{FS: coreruleset.FS}).
			WithRequestBodyAccess().
			WithRequestBodyLimit(config.RequestBodyLimitBytes).
			WithRequestBodyInMemoryLimit(config.RequestMemoryLimitBytes).
			WithErrorCallback(func(matched types.MatchedRule) {
				metadata := matched.Rule()
				config.Logger.Warn("waf rule matched",
					"transaction_id", matched.TransactionID(),
					"rule_id", metadata.ID(),
					"severity", fmt.Sprint(metadata.Severity()),
					"message", matched.Message(),
					"disruptive", matched.Disruptive(),
				)
				emitRuleMatch(config, matched, metadata)
			}).
			WithDirectives(directives.String()),
	)
	if err != nil {
		return nil, fmt.Errorf("initialize Coraza/OWASP CRS: %w", err)
	}
	return waf, nil
}

func emitRuleMatch(config Config, matched types.MatchedRule, metadata types.RuleMetadata) {
	if config.EventSink == nil {
		return
	}
	eventID, err := id.Random("evt_gateway_", 18)
	if err != nil {
		config.Logger.Error("generate Gateway event id", "error", err)
		return
	}
	ruleSeverity := fmt.Sprint(metadata.Severity())
	if len(ruleSeverity) > 64 || strings.ContainsAny(ruleSeverity, "\x00\r\n") {
		ruleSeverity = "unknown"
	}
	evidence := map[string]any{
		"rule_id":               metadata.ID(),
		"rule_severity":         ruleSeverity,
		"disruptive":            matched.Disruptive(),
		"mode":                  config.Mode,
		"request_data_included": false,
	}
	transactionID := matched.TransactionID()
	if transactionID != "" && len(transactionID) <= 128 && !strings.ContainsAny(transactionID, "\x00\r\n") {
		evidence["transaction_id"] = transactionID
	}
	event := domain.Event{
		ID: eventID, Kind: "gateway.waf.rule_match", Severity: gatewaySeverity(ruleSeverity),
		Summary: "OWASP CRS rule matched an inspected request", OccurredAt: config.Now().UTC(), Evidence: evidence,
	}
	if err := config.EventSink.Emit(event); err != nil {
		config.Logger.Warn("queue Gateway rule event failed", "rule_id", metadata.ID(), "error", err)
	}
}

func gatewaySeverity(ruleSeverity string) domain.Severity {
	switch strings.ToLower(ruleSeverity) {
	case "emergency", "alert", "critical":
		return domain.SeverityCritical
	case "error":
		return domain.SeverityHigh
	case "warning", "warn":
		return domain.SeverityMedium
	case "notice":
		return domain.SeverityLow
	case "info", "debug":
		return domain.SeverityInfo
	default:
		return domain.SeverityMedium
	}
}

// portableRuleFS compensates for filepath-based separators used by the
// SecLang include parser. Embedded filesystems always use slash-separated
// paths, including when the gateway is developed or tested on Windows.
type portableRuleFS struct {
	fs.FS
}

func (rules portableRuleFS) Open(name string) (fs.File, error) {
	return rules.FS.Open(strings.ReplaceAll(name, "\\", "/"))
}

func (rules portableRuleFS) ReadFile(name string) ([]byte, error) {
	name = strings.ReplaceAll(name, "\\", "/")
	if reader, ok := rules.FS.(fs.ReadFileFS); ok {
		return reader.ReadFile(name)
	}
	return fs.ReadFile(rules.FS, name)
}

func parseUpstream(raw string) (*url.URL, error) {
	upstream, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return nil, errors.New("upstream must be an absolute HTTP(S) URL")
	}
	if upstream.Scheme != "http" && upstream.Scheme != "https" {
		return nil, errors.New("upstream scheme must be http or https")
	}
	if upstream.User != nil || upstream.RawQuery != "" || upstream.Fragment != "" {
		return nil, errors.New("upstream must not contain credentials, query, or fragment")
	}
	return upstream, nil
}

type responseStatus struct {
	http.ResponseWriter
	status int
}

func (writer *responseStatus) Unwrap() http.ResponseWriter {
	return writer.ResponseWriter
}

func (writer *responseStatus) WriteHeader(status int) {
	if writer.status != 0 {
		return
	}
	writer.status = status
	writer.ResponseWriter.WriteHeader(status)
}

func (writer *responseStatus) Write(data []byte) (int, error) {
	if writer.status == 0 {
		writer.WriteHeader(http.StatusOK)
	}
	return writer.ResponseWriter.Write(data)
}

func requestLog(logger *slog.Logger, mode Mode, next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		started := time.Now()
		wrapped := &responseStatus{ResponseWriter: writer}
		next.ServeHTTP(wrapped, request)
		status := wrapped.status
		if status == 0 {
			status = http.StatusOK
		}
		logger.Info("gateway request",
			"method", request.Method,
			"mode", mode,
			"status", status,
			"duration_ms", time.Since(started).Milliseconds(),
		)
	})
}
