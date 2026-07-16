package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

const maxControlResponseBytes = int64(1 << 20)

type ClientConfig struct {
	BaseURL           string
	BootstrapToken    string
	HTTPClient        *http.Client
	AllowInsecureHTTP bool
}

type Client struct {
	baseURL        string
	bootstrapToken string
	httpClient     *http.Client
}

func NewClient(config ClientConfig) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(config.BaseURL))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("control URL must be an absolute HTTP(S) URL without credentials, query, or fragment")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, errors.New("control URL scheme must be http or https")
	}
	if parsed.Scheme == "http" && !config.AllowInsecureHTTP && !isLoopbackHost(parsed.Hostname()) {
		return nil, errors.New("plain HTTP is only allowed for loopback development endpoints")
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	return &Client{
		baseURL:        strings.TrimRight(parsed.String(), "/"),
		bootstrapToken: config.BootstrapToken,
		httpClient:     config.HTTPClient,
	}, nil
}

type registerInput struct {
	MachineID    string `json:"machine_id"`
	Hostname     string `json:"hostname"`
	Version      string `json:"version"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	ClientCSR    string `json:"client_csr,omitempty"`
}

type registerOutput struct {
	AgentID             string `json:"agent_id"`
	Credential          string `json:"credential"`
	ClientCertificate   string `json:"client_certificate,omitempty"`
	ClientCACertificate string `json:"client_ca_certificate,omitempty"`
}

func (client *Client) Register(ctx context.Context, input registerInput) (registerOutput, error) {
	if strings.TrimSpace(client.bootstrapToken) == "" {
		return registerOutput{}, errors.New("bootstrap token is required for registration")
	}
	var output registerOutput
	if err := client.doJSON(ctx, http.MethodPost, "/v1/agents/register", client.bootstrapToken, input, &output); err != nil {
		return registerOutput{}, err
	}
	if output.AgentID == "" || output.Credential == "" {
		return registerOutput{}, errors.New("control plane returned incomplete registration credentials")
	}
	return output, nil
}

func (client *Client) Heartbeat(ctx context.Context, identity Identity, version string, queueDepth int) error {
	path := "/v1/agents/" + url.PathEscape(identity.AgentID) + "/heartbeat"
	payload := map[string]any{"agent_version": version, "queue_depth": queueDepth}
	return client.doJSON(ctx, http.MethodPost, path, identity.Credential, payload, nil)
}

func (client *Client) SendEvents(ctx context.Context, identity Identity, events []domain.Event) error {
	path := "/v1/agents/" + url.PathEscape(identity.AgentID) + "/events"
	payload := map[string]any{"events": events}
	return client.doJSON(ctx, http.MethodPost, path, identity.Credential, payload, nil)
}

func (client *Client) RenewCertificate(ctx context.Context, identity Identity, clientCSR string) (registerOutput, error) {
	if !identity.Registered() || strings.TrimSpace(clientCSR) == "" {
		return registerOutput{}, errors.New("registered Agent identity and CSR are required")
	}
	path := "/v1/agents/" + url.PathEscape(identity.AgentID) + "/certificate"
	var output registerOutput
	if err := client.doJSON(ctx, http.MethodPost, path, identity.Credential, map[string]string{"client_csr": clientCSR}, &output); err != nil {
		return registerOutput{}, err
	}
	if output.AgentID != identity.AgentID || output.ClientCertificate == "" || output.ClientCACertificate == "" {
		return registerOutput{}, errors.New("control plane returned incomplete renewed certificate material")
	}
	return output, nil
}

func (client *Client) FetchPolicy(ctx context.Context, identity Identity) (domain.Policy, bool, error) {
	if !identity.Registered() {
		return domain.Policy{}, false, errors.New("registered Agent identity is required")
	}
	path := "/v1/agents/" + url.PathEscape(identity.AgentID) + "/policy"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, client.baseURL+path, nil)
	if err != nil {
		return domain.Policy{}, false, err
	}
	request.Header.Set("Authorization", "Bearer "+identity.Credential)
	request.Header.Set("User-Agent", "my-safe-agent/"+Version)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return domain.Policy{}, false, fmt.Errorf("fetch Agent policy: %w", err)
	}
	defer response.Body.Close()
	content, err := io.ReadAll(io.LimitReader(response.Body, maxControlResponseBytes+1))
	if err != nil {
		return domain.Policy{}, false, err
	}
	if int64(len(content)) > maxControlResponseBytes {
		return domain.Policy{}, false, errors.New("control response exceeds size limit")
	}
	if response.StatusCode == http.StatusNotFound {
		return domain.Policy{}, false, nil
	}
	if response.StatusCode != http.StatusOK {
		return domain.Policy{}, false, fmt.Errorf("control response %d: %s", response.StatusCode, http.StatusText(response.StatusCode))
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var policy domain.Policy
	if err := decoder.Decode(&policy); err != nil {
		return domain.Policy{}, false, fmt.Errorf("decode Agent policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domain.Policy{}, false, errors.New("Agent policy contains trailing JSON")
	}
	if policy.AgentID != identity.AgentID {
		return domain.Policy{}, false, errors.New("Agent policy target does not match the authenticated Agent")
	}
	if err := domain.ValidatePolicy(policy); err != nil {
		return domain.Policy{}, false, err
	}
	return policy, true, nil
}

func (client *Client) doJSON(ctx context.Context, method, path, token string, input, output any) error {
	encoded, err := json.Marshal(input)
	if err != nil {
		return fmt.Errorf("encode control request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return fmt.Errorf("create control request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("User-Agent", "my-safe-agent/"+Version)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return fmt.Errorf("send control request: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxControlResponseBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return fmt.Errorf("read control response: %w", err)
	}
	if int64(len(content)) > maxControlResponseBytes {
		return errors.New("control response exceeds size limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var problem struct {
			Detail string `json:"detail"`
		}
		_ = json.Unmarshal(content, &problem)
		if problem.Detail == "" {
			problem.Detail = http.StatusText(response.StatusCode)
		}
		return fmt.Errorf("control response %d: %s", response.StatusCode, problem.Detail)
	}
	if output != nil {
		if err := json.Unmarshal(content, output); err != nil {
			return fmt.Errorf("decode control response: %w", err)
		}
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}
