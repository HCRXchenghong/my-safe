package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/detector/fileintegrity"
	"github.com/HCRXchenghong/my-safe/internal/detector/runtimewatch"
	"github.com/HCRXchenghong/my-safe/internal/detector/sshauth"
	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/id"
	"github.com/HCRXchenghong/my-safe/internal/localfeed"
	"github.com/HCRXchenghong/my-safe/internal/mtls"
	"github.com/HCRXchenghong/my-safe/internal/scanner"
)

// Version is replaced by release builds through -ldflags -X.
var Version = "0.1.0-dev"

type Config struct {
	StateDir                 string
	ControlURL               string
	BootstrapToken           string
	HTTPClient               *http.Client
	AllowInsecureHTTP        bool
	Interval                 time.Duration
	Logger                   *slog.Logger
	Now                      func() time.Time
	DisableFileIntegrity     bool
	FileWatchPaths           []string
	DisableSSHAuth           bool
	SSHAuthLogPaths          []string
	SSHThreshold             int
	SSHWindow                time.Duration
	DisableRuntimeWatch      bool
	ProcRoot                 string
	DisableGatewayFeed       bool
	GatewayEventSocket       string
	CertificateRenewalWindow time.Duration
}

func RunOnce(ctx context.Context, config Config) error {
	_, err := runCycle(ctx, normalizeConfig(config))
	return err
}

func Run(ctx context.Context, config Config) error {
	config = normalizeConfig(config)
	if config.Interval < 10*time.Second {
		return errors.New("scan interval must be at least 10 seconds")
	}
	wake := make(chan struct{}, 1)
	var feedErrors <-chan error
	if !config.DisableGatewayFeed && config.GatewayEventSocket != "" {
		queue, err := OpenEncryptedQueue(config.StateDir)
		if err != nil {
			return fmt.Errorf("open Gateway event queue: %w", err)
		}
		errors := make(chan error, 1)
		feedErrors = errors
		go func() {
			errors <- localfeed.Listen(ctx, config.GatewayEventSocket, func(event domain.Event) error {
				if err := queue.Enqueue(event); err != nil {
					return err
				}
				select {
				case wake <- struct{}{}:
				default:
				}
				return nil
			})
		}()
	}
	for {
		if _, err := runCycle(ctx, config); err != nil && !errors.Is(err, context.Canceled) {
			config.Logger.Warn("agent cycle failed; encrypted queue retained", "error", err)
		}
		timer := time.NewTimer(config.Interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case err := <-feedErrors:
			timer.Stop()
			if err != nil {
				return fmt.Errorf("Gateway event feed stopped: %w", err)
			}
			return nil
		case <-wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func runCycle(ctx context.Context, config Config) (int, error) {
	if config.CertificateRenewalWindow < time.Hour || config.CertificateRenewalWindow > 30*24*time.Hour {
		return 0, errors.New("certificate renewal window must be between 1 hour and 30 days")
	}
	identity, err := LoadIdentity(config.StateDir)
	if err != nil {
		return 0, fmt.Errorf("load identity: %w", err)
	}
	if identity.Registered() {
		policy, exists, policyErr := LoadPolicy(config.StateDir, identity.AgentID)
		if policyErr != nil {
			return 0, fmt.Errorf("load Agent policy: %w", policyErr)
		}
		if exists {
			config = applyPolicy(config, policy)
		}
	}
	queue, err := OpenEncryptedQueue(config.StateDir)
	if err != nil {
		return 0, fmt.Errorf("open encrypted queue: %w", err)
	}
	var fileDetector *fileintegrity.Detector
	if !config.DisableFileIntegrity && len(config.FileWatchPaths) > 0 {
		fileDetector, err = fileintegrity.New(fileintegrity.Config{
			StateDir: config.StateDir,
			Paths:    config.FileWatchPaths,
			Now:      config.Now,
		})
		if err != nil {
			return 0, fmt.Errorf("configure file integrity detector: %w", err)
		}
	}
	var sshDetector *sshauth.Detector
	if !config.DisableSSHAuth && len(config.SSHAuthLogPaths) > 0 {
		sshDetector, err = sshauth.New(sshauth.Config{
			StateDir:  config.StateDir,
			Paths:     config.SSHAuthLogPaths,
			Now:       config.Now,
			Threshold: config.SSHThreshold,
			Window:    config.SSHWindow,
		})
		if err != nil {
			return 0, fmt.Errorf("configure SSH auth detector: %w", err)
		}
	}
	var runtimeDetector *runtimewatch.Detector
	if !config.DisableRuntimeWatch && (runtimewatch.DefaultEnabled() || config.ProcRoot != "") {
		runtimeDetector, err = runtimewatch.New(runtimewatch.Config{
			StateDir: config.StateDir,
			ProcRoot: config.ProcRoot,
			Now:      config.Now,
		})
		if err != nil {
			return 0, fmt.Errorf("configure runtime detector: %w", err)
		}
	}
	event, err := (scanner.Scanner{Now: config.Now}).Scan(ctx)
	if err != nil {
		return 0, fmt.Errorf("scan host: %w", err)
	}
	events := []domain.Event{event}
	var fileResult fileintegrity.Result
	if fileDetector != nil {
		fileResult, err = fileDetector.Scan(ctx)
		if err != nil {
			config.Logger.Warn("file integrity scan failed; baseline retained", "error", err)
			diagnostic, diagnosticErr := detectorErrorEvent(config.Now(), "file.integrity.error", "File integrity detector could not read its baseline")
			if diagnosticErr != nil {
				return 0, diagnosticErr
			}
			events = append(events, diagnostic)
		} else {
			events = append(events, fileResult.Events...)
		}
	}
	var sshResult sshauth.Result
	if sshDetector != nil {
		sshResult, err = sshDetector.Scan(ctx)
		if err != nil {
			config.Logger.Warn("SSH auth scan failed; cursor retained", "error", err)
			diagnostic, diagnosticErr := detectorErrorEvent(config.Now(), "ssh.auth.error", "SSH authentication detector could not read its state")
			if diagnosticErr != nil {
				return 0, diagnosticErr
			}
			events = append(events, diagnostic)
		} else {
			events = append(events, sshResult.Events...)
		}
	}
	var runtimeResult runtimewatch.Result
	if runtimeDetector != nil {
		runtimeResult, err = runtimeDetector.Scan(ctx)
		if err != nil {
			config.Logger.Warn("runtime scan failed; baseline retained", "error", err)
			diagnostic, diagnosticErr := detectorErrorEvent(config.Now(), "runtime.error", "Runtime process and port detector could not read its state")
			if diagnosticErr != nil {
				return 0, diagnosticErr
			}
			events = append(events, diagnostic)
		} else {
			events = append(events, runtimeResult.Events...)
		}
	}
	for _, observed := range events {
		if err := queue.Enqueue(observed); err != nil {
			return 0, fmt.Errorf("queue observed event: %w", err)
		}
	}
	if fileResult.Commit != nil {
		if err := fileResult.Commit(); err != nil {
			return 0, fmt.Errorf("commit file integrity baseline: %w", err)
		}
	}
	if sshResult.Commit != nil {
		if err := sshResult.Commit(); err != nil {
			return 0, fmt.Errorf("commit SSH auth cursor: %w", err)
		}
	}
	if runtimeResult.Commit != nil {
		if err := runtimeResult.Commit(); err != nil {
			return 0, fmt.Errorf("commit runtime baseline: %w", err)
		}
	}

	httpClient := config.HTTPClient
	certificateNeedsRenewal := false
	if identity.Registered() {
		certificate, exists, certificateErr := mtls.LoadClientCertificate(config.StateDir, config.Now())
		if certificateErr != nil {
			return 0, certificateErr
		}
		if exists {
			certificateNeedsRenewal = certificate.Leaf != nil && certificate.Leaf.NotAfter.Sub(config.Now()) <= config.CertificateRenewalWindow
			httpClient, err = mtls.HTTPClientWithCertificate(httpClient, certificate)
			if err != nil {
				return 0, err
			}
		}
	}
	client, err := NewClient(ClientConfig{
		BaseURL:           config.ControlURL,
		BootstrapToken:    config.BootstrapToken,
		HTTPClient:        httpClient,
		AllowInsecureHTTP: config.AllowInsecureHTTP,
	})
	if err != nil {
		return 0, err
	}
	if !identity.Registered() {
		clientCSR, err := mtls.EnsureClientCSR(config.StateDir, identity.MachineID)
		if err != nil {
			return 0, fmt.Errorf("create Agent mTLS request: %w", err)
		}
		hostname, err := os.Hostname()
		if err != nil || hostname == "" {
			hostname = "unknown-host"
		}
		registration, err := client.Register(ctx, registerInput{
			MachineID:    identity.MachineID,
			Hostname:     hostname,
			Version:      Version,
			Platform:     runtime.GOOS,
			Architecture: runtime.GOARCH,
			ClientCSR:    string(clientCSR),
		})
		if err != nil {
			return 0, fmt.Errorf("register agent: %w", err)
		}
		identity.AgentID = registration.AgentID
		identity.Credential = registration.Credential
		if registration.ClientCertificate != "" || registration.ClientCACertificate != "" {
			if registration.ClientCertificate == "" || registration.ClientCACertificate == "" {
				return 0, errors.New("control plane returned incomplete Agent mTLS material")
			}
			if err := mtls.SaveIssuedClientCertificate(config.StateDir, identity.AgentID, []byte(registration.ClientCertificate), []byte(registration.ClientCACertificate), config.Now()); err != nil {
				return 0, fmt.Errorf("save Agent mTLS certificate: %w", err)
			}
			certificate, exists, err := mtls.LoadClientCertificate(config.StateDir, config.Now())
			if err != nil || !exists {
				return 0, errors.Join(errors.New("load issued Agent mTLS certificate"), err)
			}
			httpClient, err = mtls.HTTPClientWithCertificate(config.HTTPClient, certificate)
			if err != nil {
				return 0, err
			}
			client, err = NewClient(ClientConfig{
				BaseURL: config.ControlURL, BootstrapToken: config.BootstrapToken,
				HTTPClient: httpClient, AllowInsecureHTTP: config.AllowInsecureHTTP,
			})
			if err != nil {
				return 0, err
			}
		}
		if err := SaveCredentials(config.StateDir, identity); err != nil {
			return 0, fmt.Errorf("persist registration credentials: %w", err)
		}
	}
	if identity.Registered() && certificateNeedsRenewal {
		clientCSR, err := mtls.EnsureClientCSR(config.StateDir, identity.MachineID)
		if err != nil {
			return 0, fmt.Errorf("create Agent certificate renewal request: %w", err)
		}
		renewal, err := client.RenewCertificate(ctx, identity, string(clientCSR))
		if err != nil {
			return 0, fmt.Errorf("renew Agent mTLS certificate: %w", err)
		}
		if err := mtls.SaveIssuedClientCertificate(config.StateDir, identity.AgentID, []byte(renewal.ClientCertificate), []byte(renewal.ClientCACertificate), config.Now()); err != nil {
			return 0, fmt.Errorf("save renewed Agent mTLS certificate: %w", err)
		}
		certificate, exists, err := mtls.LoadClientCertificate(config.StateDir, config.Now())
		if err != nil || !exists {
			return 0, errors.Join(errors.New("load renewed Agent mTLS certificate"), err)
		}
		httpClient, err = mtls.HTTPClientWithCertificate(config.HTTPClient, certificate)
		if err != nil {
			return 0, err
		}
		client, err = NewClient(ClientConfig{
			BaseURL: config.ControlURL, BootstrapToken: config.BootstrapToken,
			HTTPClient: httpClient, AllowInsecureHTTP: config.AllowInsecureHTTP,
		})
		if err != nil {
			return 0, err
		}
	}
	remotePolicy, policyExists, err := client.FetchPolicy(ctx, identity)
	if err != nil {
		return 0, fmt.Errorf("fetch Agent policy: %w", err)
	}
	if policyExists {
		localPolicy, localExists, err := LoadPolicy(config.StateDir, identity.AgentID)
		if err != nil {
			return 0, err
		}
		if !localExists || remotePolicy.Revision > localPolicy.Revision {
			if err := SavePolicy(config.StateDir, remotePolicy); err != nil {
				return 0, fmt.Errorf("persist Agent policy: %w", err)
			}
		} else if remotePolicy.Revision < localPolicy.Revision {
			return 0, errors.New("control plane returned a stale Agent policy revision")
		}
	}

	queueDepth, err := queue.Len()
	if err != nil {
		return 0, err
	}
	if err := client.Heartbeat(ctx, identity, Version, queueDepth); err != nil {
		return 0, fmt.Errorf("send heartbeat: %w", err)
	}
	flushed := 0
	for {
		batch, err := queue.Peek(100)
		if err != nil {
			return flushed, err
		}
		if len(batch.Events) == 0 {
			break
		}
		if err := client.SendEvents(ctx, identity, batch.Events); err != nil {
			return flushed, fmt.Errorf("send queued events: %w", err)
		}
		if err := queue.Ack(batch); err != nil {
			return flushed, err
		}
		flushed += len(batch.Events)
	}
	config.Logger.Info("agent cycle completed", "flushed_events", flushed)
	return flushed, nil
}

func normalizeConfig(config Config) Config {
	if config.Interval == 0 {
		config.Interval = time.Minute
	}
	if config.Logger == nil {
		config.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.CertificateRenewalWindow == 0 {
		config.CertificateRenewalWindow = 7 * 24 * time.Hour
	}
	if !config.DisableFileIntegrity && config.FileWatchPaths == nil {
		config.FileWatchPaths = fileintegrity.DefaultPaths()
	}
	if !config.DisableSSHAuth && config.SSHAuthLogPaths == nil {
		config.SSHAuthLogPaths = sshauth.DefaultPaths()
	}
	if !config.DisableGatewayFeed && config.GatewayEventSocket == "" && runtime.GOOS == "linux" {
		config.GatewayEventSocket = "/run/my-safe/gateway-events.sock"
	}
	return config
}

func applyPolicy(config Config, policy domain.Policy) Config {
	if !policy.FileIntegrityEnabled {
		config.DisableFileIntegrity = true
	} else if !config.DisableFileIntegrity && len(policy.FileWatchPaths) > 0 {
		config.FileWatchPaths = append([]string(nil), policy.FileWatchPaths...)
	}
	if !policy.SSHAuthEnabled {
		config.DisableSSHAuth = true
	} else if !config.DisableSSHAuth {
		config.SSHThreshold = policy.SSHThreshold
		config.SSHWindow = time.Duration(policy.SSHWindowSeconds) * time.Second
	}
	if !policy.RuntimeWatchEnabled {
		config.DisableRuntimeWatch = true
	}
	return config
}

func detectorErrorEvent(now time.Time, kind, summary string) (domain.Event, error) {
	eventID, err := id.Random("evt_", 18)
	if err != nil {
		return domain.Event{}, fmt.Errorf("generate detector error event id: %w", err)
	}
	return domain.Event{
		ID:         eventID,
		Kind:       kind,
		Severity:   domain.SeverityHigh,
		Summary:    summary,
		OccurredAt: now.UTC(),
		Evidence:   map[string]any{"baseline_retained": true, "read_only": true},
	}, nil
}
