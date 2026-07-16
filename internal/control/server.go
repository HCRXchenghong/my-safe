package control

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/id"
	"github.com/HCRXchenghong/my-safe/internal/mtls"
	"github.com/HCRXchenghong/my-safe/internal/security"
	"github.com/HCRXchenghong/my-safe/internal/store"
)

const (
	defaultMaxBodyBytes = int64(1 << 20)
	maxEventBatch       = 100
)

type Config struct {
	Store            store.Store
	BootstrapToken   string
	AdminToken       string
	Logger           *slog.Logger
	Now              func() time.Time
	MaxBodyBytes     int64
	AgentIssuer      *mtls.Issuer
	RequireAgentMTLS bool
}

type Server struct {
	store            store.Store
	bootstrapToken   string
	adminToken       string
	logger           *slog.Logger
	now              func() time.Time
	maxBodyBytes     int64
	agentIssuer      *mtls.Issuer
	requireAgentMTLS bool
	handler          http.Handler
}

func New(config Config) (*Server, error) {
	if config.Store == nil {
		return nil, errors.New("store is required")
	}
	if len(config.BootstrapToken) < 16 {
		return nil, errors.New("bootstrap token must contain at least 16 bytes")
	}
	if len(config.AdminToken) < 16 {
		return nil, errors.New("admin token must contain at least 16 bytes")
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxBodyBytes <= 0 {
		config.MaxBodyBytes = defaultMaxBodyBytes
	}
	if config.RequireAgentMTLS && config.AgentIssuer == nil {
		return nil, errors.New("required Agent mTLS needs an Agent certificate issuer")
	}

	server := &Server{
		store:            config.Store,
		bootstrapToken:   config.BootstrapToken,
		adminToken:       config.AdminToken,
		logger:           config.Logger,
		now:              config.Now,
		maxBodyBytes:     config.MaxBodyBytes,
		agentIssuer:      config.AgentIssuer,
		requireAgentMTLS: config.RequireAgentMTLS,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", server.health)
	mux.HandleFunc("POST /v1/agents/register", server.registerAgent)
	mux.HandleFunc("POST /v1/agents/{agentID}/heartbeat", server.heartbeat)
	mux.HandleFunc("POST /v1/agents/{agentID}/events", server.ingestEvents)
	mux.HandleFunc("POST /v1/agents/{agentID}/certificate", server.renewAgentCertificate)
	mux.HandleFunc("GET /v1/agents", server.listAgents)
	mux.HandleFunc("GET /v1/alerts", server.listAlerts)
	mux.HandleFunc("GET /v1/agents/{agentID}/policy", server.getAgentPolicy)
	mux.HandleFunc("PUT /v1/agents/{agentID}/policy", server.putAgentPolicy)
	mux.HandleFunc("GET /v1/audit-logs", server.listAuditLogs)
	server.handler = server.middleware(mux)
	return server, nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.handler.ServeHTTP(writer, request)
}

func (s *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

type registrationRequest struct {
	MachineID    string `json:"machine_id"`
	Hostname     string `json:"hostname"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	ClientCSR    string `json:"client_csr,omitempty"`
}

type registrationResponse struct {
	AgentID             string `json:"agent_id"`
	Credential          string `json:"credential"`
	ClientCertificate   string `json:"client_certificate,omitempty"`
	ClientCACertificate string `json:"client_ca_certificate,omitempty"`
}

func (s *Server) registerAgent(writer http.ResponseWriter, request *http.Request) {
	if !s.authorizeToken(request, s.bootstrapToken) {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input registrationRequest
	if err := decodeJSON(writer, request, &input, s.maxBodyBytes); err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if err := domain.ValidateRegistration(input.MachineID, input.Hostname, input.Version, input.Platform, input.Architecture); err != nil {
		writeProblem(writer, http.StatusBadRequest, err.Error())
		return
	}
	if _, err := s.store.AgentByMachineID(request.Context(), input.MachineID); err == nil {
		writeProblem(writer, http.StatusConflict, "machine is already registered")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		s.internalError(writer, request, "lookup agent", err)
		return
	}

	agentID, err := id.Random("agt_", 18)
	if err != nil {
		s.internalError(writer, request, "generate agent id", err)
		return
	}
	credential, err := id.Random("msc_", 32)
	if err != nil {
		s.internalError(writer, request, "generate credential", err)
		return
	}
	now := s.now().UTC()
	clientCertificate := []byte(nil)
	if s.agentIssuer != nil {
		if strings.TrimSpace(input.ClientCSR) == "" || len(input.ClientCSR) > 32<<10 {
			writeProblem(writer, http.StatusBadRequest, "a bounded Agent client CSR is required")
			return
		}
		clientCertificate, err = s.agentIssuer.Issue([]byte(input.ClientCSR), agentID, input.MachineID, now)
		if err != nil {
			writeProblem(writer, http.StatusBadRequest, "invalid Agent client CSR")
			return
		}
	}
	hash := sha256.Sum256([]byte(credential))
	agent := domain.Agent{
		ID:             agentID,
		MachineID:      input.MachineID,
		Hostname:       input.Hostname,
		Version:        input.Version,
		Platform:       input.Platform,
		Architecture:   input.Architecture,
		CredentialHash: hash[:],
		RegisteredAt:   now,
		LastSeenAt:     now,
	}
	if err := s.store.CreateAgent(request.Context(), agent); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeProblem(writer, http.StatusConflict, "machine is already registered")
			return
		}
		s.internalError(writer, request, "create agent", err)
		return
	}
	response := registrationResponse{AgentID: agentID, Credential: credential}
	if len(clientCertificate) > 0 {
		response.ClientCertificate = string(clientCertificate)
		response.ClientCACertificate = string(s.agentIssuer.CertificatePEM())
	}
	writeJSON(writer, http.StatusCreated, response)
}

type heartbeatRequest struct {
	AgentVersion string `json:"agent_version"`
	QueueDepth   int    `json:"queue_depth"`
}

type certificateRequest struct {
	ClientCSR string `json:"client_csr"`
}

func (s *Server) renewAgentCertificate(writer http.ResponseWriter, request *http.Request) {
	agentID := request.PathValue("agentID")
	if s.agentIssuer == nil || !s.authorizeAgent(request, agentID) {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input certificateRequest
	if err := decodeJSON(writer, request, &input, s.maxBodyBytes); err != nil || strings.TrimSpace(input.ClientCSR) == "" || len(input.ClientCSR) > 32<<10 {
		writeProblem(writer, http.StatusBadRequest, "invalid Agent client CSR")
		return
	}
	agent, err := s.store.AgentByID(request.Context(), agentID)
	if err != nil {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	certificate, err := s.agentIssuer.Issue([]byte(input.ClientCSR), agentID, agent.MachineID, s.now().UTC())
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid Agent client CSR")
		return
	}
	writeJSON(writer, http.StatusOK, registrationResponse{
		AgentID: agentID, ClientCertificate: string(certificate), ClientCACertificate: string(s.agentIssuer.CertificatePEM()),
	})
}

func (s *Server) heartbeat(writer http.ResponseWriter, request *http.Request) {
	agentID := request.PathValue("agentID")
	if !s.authorizeAgent(request, agentID) {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input heartbeatRequest
	if err := decodeJSON(writer, request, &input, s.maxBodyBytes); err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if input.QueueDepth < 0 || input.QueueDepth > 1_000_000 || len(input.AgentVersion) > 64 {
		writeProblem(writer, http.StatusBadRequest, "invalid heartbeat")
		return
	}
	heartbeat := domain.Heartbeat{
		AgentVersion: input.AgentVersion,
		QueueDepth:   input.QueueDepth,
		SentAt:       s.now().UTC(),
	}
	if err := s.store.UpdateHeartbeat(request.Context(), agentID, heartbeat); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeProblem(writer, http.StatusUnauthorized, "unauthorized")
			return
		}
		s.internalError(writer, request, "update heartbeat", err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]string{"status": "accepted"})
}

type eventBatchRequest struct {
	Events []domain.Event `json:"events"`
}

func (s *Server) ingestEvents(writer http.ResponseWriter, request *http.Request) {
	agentID := request.PathValue("agentID")
	if !s.authorizeAgent(request, agentID) {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	var input eventBatchRequest
	if err := decodeJSON(writer, request, &input, s.maxBodyBytes); err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if len(input.Events) == 0 || len(input.Events) > maxEventBatch {
		writeProblem(writer, http.StatusBadRequest, fmt.Sprintf("events must contain between 1 and %d entries", maxEventBatch))
		return
	}
	now := s.now().UTC()
	for index := range input.Events {
		event := &input.Events[index]
		event.AgentID = agentID
		event.ReceivedAt = now
		event.Evidence = security.RedactMap(event.Evidence)
		if err := domain.ValidateEvent(*event, now); err != nil {
			writeProblem(writer, http.StatusBadRequest, fmt.Sprintf("event %d: %v", index, err))
			return
		}
	}
	inserted, err := s.store.SaveEvents(request.Context(), input.Events)
	if err != nil {
		s.internalError(writer, request, "save events", err)
		return
	}
	writeJSON(writer, http.StatusAccepted, map[string]int{
		"accepted":   inserted,
		"duplicates": len(input.Events) - inserted,
	})
}

func (s *Server) listAgents(writer http.ResponseWriter, request *http.Request) {
	if !s.authorizeToken(request, s.adminToken) {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	limit, err := queryLimit(request)
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, err.Error())
		return
	}
	agents, err := s.store.ListAgents(request.Context(), limit)
	if err != nil {
		s.internalError(writer, request, "list agents", err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"agents": agents})
}

func (s *Server) listAlerts(writer http.ResponseWriter, request *http.Request) {
	if !s.authorizeToken(request, s.adminToken) {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	limit, err := queryLimit(request)
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, err.Error())
		return
	}
	severity := domain.Severity(strings.ToLower(request.URL.Query().Get("severity")))
	if severity != "" && !severity.Valid() {
		writeProblem(writer, http.StatusBadRequest, "severity is invalid")
		return
	}
	alerts, err := s.store.ListAlerts(request.Context(), domain.AlertFilter{Severity: severity, Limit: limit})
	if err != nil {
		s.internalError(writer, request, "list alerts", err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"alerts": alerts})
}

type policyRequest struct {
	ExpectedRevision     int64    `json:"expected_revision"`
	FileIntegrityEnabled *bool    `json:"file_integrity_enabled"`
	FileWatchPaths       []string `json:"file_watch_paths"`
	SSHAuthEnabled       *bool    `json:"ssh_auth_enabled"`
	SSHThreshold         int      `json:"ssh_threshold"`
	SSHWindowSeconds     int      `json:"ssh_window_seconds"`
	RuntimeWatchEnabled  *bool    `json:"runtime_watch_enabled"`
}

func (s *Server) getAgentPolicy(writer http.ResponseWriter, request *http.Request) {
	agentID := request.PathValue("agentID")
	if !s.authorizeAgent(request, agentID) {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	policy, err := s.store.PolicyForAgent(request.Context(), agentID)
	if errors.Is(err, store.ErrNotFound) {
		writeProblem(writer, http.StatusNotFound, "Agent policy is not configured")
		return
	}
	if err != nil {
		s.internalError(writer, request, "read Agent policy", err)
		return
	}
	writeJSON(writer, http.StatusOK, policy)
}

func (s *Server) putAgentPolicy(writer http.ResponseWriter, request *http.Request) {
	if !s.authorizeToken(request, s.adminToken) {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	agentID := request.PathValue("agentID")
	if _, err := s.store.AgentByID(request.Context(), agentID); err != nil {
		writeProblem(writer, http.StatusNotFound, "Agent does not exist")
		return
	}
	var input policyRequest
	if err := decodeJSON(writer, request, &input, s.maxBodyBytes); err != nil {
		writeProblem(writer, http.StatusBadRequest, "invalid JSON request")
		return
	}
	if err := validatePolicyRequest(input); err != nil {
		writeProblem(writer, http.StatusBadRequest, err.Error())
		return
	}
	policyID := ""
	if input.ExpectedRevision == 0 {
		var err error
		policyID, err = id.Random("pol_", 18)
		if err != nil {
			s.internalError(writer, request, "generate policy id", err)
			return
		}
	} else {
		current, err := s.store.PolicyForAgent(request.Context(), agentID)
		if err != nil || current.Revision != input.ExpectedRevision {
			writeProblem(writer, http.StatusConflict, "policy revision conflict")
			return
		}
		policyID = current.ID
	}
	paths := append([]string(nil), input.FileWatchPaths...)
	sort.Strings(paths)
	now := s.now().UTC()
	policy := domain.Policy{
		ID: policyID, AgentID: agentID, Revision: input.ExpectedRevision + 1,
		FileIntegrityEnabled: *input.FileIntegrityEnabled, FileWatchPaths: paths,
		SSHAuthEnabled: *input.SSHAuthEnabled, SSHThreshold: input.SSHThreshold,
		SSHWindowSeconds: input.SSHWindowSeconds, RuntimeWatchEnabled: *input.RuntimeWatchEnabled,
		UpdatedAt: now,
	}
	if err := domain.ValidatePolicy(policy); err != nil {
		writeProblem(writer, http.StatusBadRequest, err.Error())
		return
	}
	auditID, err := id.Random("aud_", 18)
	if err != nil {
		s.internalError(writer, request, "generate audit id", err)
		return
	}
	audit := domain.AuditLog{
		ID: auditID, Actor: "admin_token", Action: "agent.policy.updated",
		Resource: "agent/" + agentID + "/policy", OccurredAt: now,
		Details: map[string]any{
			"previous_revision": input.ExpectedRevision, "new_revision": policy.Revision,
			"file_watch_path_count": len(paths), "file_integrity_enabled": policy.FileIntegrityEnabled,
			"ssh_auth_enabled": policy.SSHAuthEnabled, "runtime_watch_enabled": policy.RuntimeWatchEnabled,
		},
	}
	if err := s.store.SavePolicyAndAudit(request.Context(), policy, input.ExpectedRevision, audit); err != nil {
		if errors.Is(err, store.ErrConflict) {
			writeProblem(writer, http.StatusConflict, "policy revision conflict")
			return
		}
		s.internalError(writer, request, "save Agent policy", err)
		return
	}
	writeJSON(writer, http.StatusOK, policy)
}

func (s *Server) listAuditLogs(writer http.ResponseWriter, request *http.Request) {
	if !s.authorizeToken(request, s.adminToken) {
		writeProblem(writer, http.StatusUnauthorized, "unauthorized")
		return
	}
	limit, err := queryLimit(request)
	if err != nil {
		writeProblem(writer, http.StatusBadRequest, err.Error())
		return
	}
	logs, err := s.store.ListAuditLogs(request.Context(), limit)
	if err != nil {
		s.internalError(writer, request, "list audit logs", err)
		return
	}
	for index := range logs {
		logs[index].Details = security.RedactMap(logs[index].Details)
	}
	writeJSON(writer, http.StatusOK, map[string]any{"audit_logs": logs})
}

func validatePolicyRequest(input policyRequest) error {
	if input.ExpectedRevision < 0 || input.FileIntegrityEnabled == nil || input.SSHAuthEnabled == nil || input.RuntimeWatchEnabled == nil || input.FileWatchPaths == nil {
		return errors.New("policy fields and a non-negative expected_revision are required")
	}
	if len(input.FileWatchPaths) > 64 {
		return errors.New("file_watch_paths must contain at most 64 paths")
	}
	seen := make(map[string]bool, len(input.FileWatchPaths))
	for _, item := range input.FileWatchPaths {
		if len(item) == 0 || len(item) > 512 || !strings.HasPrefix(item, "/") || path.Clean(item) != item || strings.ContainsAny(item, "\x00\r\n") {
			return errors.New("file_watch_paths contains an invalid absolute Linux path")
		}
		if seen[item] {
			return errors.New("file_watch_paths contains a duplicate")
		}
		seen[item] = true
	}
	if input.SSHThreshold < 2 || input.SSHThreshold > 100 || input.SSHWindowSeconds < 10 || input.SSHWindowSeconds > 86400 {
		return errors.New("SSH threshold or window is outside the safe range")
	}
	return nil
}

func (s *Server) authorizeAgent(request *http.Request, agentID string) bool {
	if strings.TrimSpace(agentID) == "" {
		return false
	}
	token, ok := bearerToken(request)
	if !ok {
		return false
	}
	agent, err := s.store.AgentByID(request.Context(), agentID)
	if err != nil || len(agent.CredentialHash) != sha256.Size {
		return false
	}
	hash := sha256.Sum256([]byte(token))
	if subtle.ConstantTimeCompare(hash[:], agent.CredentialHash) != 1 {
		return false
	}
	if s.requireAgentMTLS && !agentCertificateMatches(request, agentID) {
		return false
	}
	return true
}

func agentCertificateMatches(request *http.Request, agentID string) bool {
	if request.TLS == nil || len(request.TLS.VerifiedChains) == 0 || len(request.TLS.PeerCertificates) == 0 {
		return false
	}
	return mtls.MatchesAgent(request.TLS.PeerCertificates[0], agentID)
}

func (s *Server) authorizeToken(request *http.Request, expected string) bool {
	provided, ok := bearerToken(request)
	if !ok {
		return false
	}
	providedHash := sha256.Sum256([]byte(provided))
	expectedHash := sha256.Sum256([]byte(expected))
	return subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) == 1
}

func bearerToken(request *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(request.Header.Get("Authorization")), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func decodeJSON(writer http.ResponseWriter, request *http.Request, target any, limit int64) error {
	request.Body = http.MaxBytesReader(writer, request.Body, limit)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON value")
	}
	return nil
}

func queryLimit(request *http.Request) (int, error) {
	raw := request.URL.Query().Get("limit")
	if raw == "" {
		return 100, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > 500 {
		return 0, errors.New("limit must be between 1 and 500")
	}
	return limit, nil
}

func (s *Server) internalError(writer http.ResponseWriter, request *http.Request, operation string, err error) {
	s.logger.Error("control request failed", "operation", operation, "method", request.Method, "path", request.URL.Path, "error", err)
	writeProblem(writer, http.StatusInternalServerError, "internal server error")
}

func writeProblem(writer http.ResponseWriter, status int, detail string) {
	writer.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	writeJSON(writer, status, map[string]any{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
		"detail": detail,
	})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	if writer.Header().Get("Content-Type") == "" {
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	}
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
