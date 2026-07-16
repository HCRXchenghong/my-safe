package installer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/installassets"
	"github.com/HCRXchenghong/my-safe/internal/releasebundle"
)

type ApplyOptions struct {
	Root               string
	BundleDirectory    string
	ManifestPath       string
	SignaturePath      string
	ExpectedVersion    string
	ControlURL         string
	BootstrapTokenFile string
	Gateway            GatewaySelection
	Upstream           string
	GatewayPort        int
	Architecture       string
	AllowExperimental  bool
	AllowDowngrade     bool
	DryRun             bool
	SkipRegistration   bool
	SkipHealthCheck    bool
	Runner             ApplyRunner
	PublicKey          ed25519.PublicKey
	Now                func() time.Time
}

type ApplyResult struct {
	Inspection    Inspection `json:"inspection"`
	Version       string     `json:"version"`
	TransactionID string     `json:"transaction_id,omitempty"`
	Status        string     `json:"status"`
}

func Apply(ctx context.Context, options ApplyOptions) (ApplyResult, error) {
	options = normalizeApplyOptions(options)
	manifestBytes, signature, publicKey, manifest, err := verifyRelease(options)
	_ = manifestBytes
	_ = signature
	if err != nil {
		return ApplyResult{}, err
	}
	if options.ExpectedVersion != "" && manifest.Version != options.ExpectedVersion {
		return ApplyResult{}, fmt.Errorf("signed release version %q does not match requested version %q", manifest.Version, options.ExpectedVersion)
	}
	installed, installedExists, err := loadInstalledRelease(options.Root)
	if err != nil {
		return ApplyResult{}, err
	}
	if installedExists && compareReleaseVersions(manifest.Version, installed.Version) < 0 && !options.AllowDowngrade {
		return ApplyResult{}, fmt.Errorf("refusing downgrade from %s to %s without -allow-downgrade", installed.Version, manifest.Version)
	}
	inspection, err := Inspect(ctx, InspectOptions{
		Root:         options.Root,
		Architecture: options.Architecture,
		Runner:       options.Runner,
		Plan: PlanOptions{
			Gateway:     options.Gateway,
			Upstream:    options.Upstream,
			GatewayPort: options.GatewayPort,
		},
	})
	if err != nil {
		return ApplyResult{}, err
	}
	result := ApplyResult{Inspection: inspection, Version: manifest.Version, Status: "planned"}
	if !inspection.Plan.Installable {
		return result, errors.New("installation plan is blocked")
	}
	if inspection.Environment.Support == SupportExperimental && !options.AllowExperimental {
		return result, errors.New("experimental platform requires -allow-experimental")
	}
	components := []string{"agent"}
	if inspection.Plan.GatewayEnabled {
		components = append(components, "gateway")
	}
	if err := releasebundle.VerifySelection(options.BundleDirectory, manifest, "linux", inspection.Environment.Architecture, components...); err != nil {
		return result, err
	}
	if err := validateControlURL(options.ControlURL); err != nil {
		return result, err
	}
	if options.DryRun {
		return result, nil
	}
	if samePath(options.Root, string(filepath.Separator)) && !hasRootPrivileges() {
		return result, errors.New("installation into / requires root privileges")
	}
	bootstrapToken := ""
	if !options.SkipRegistration {
		bootstrapToken, err = readBootstrapToken(options.BootstrapTokenFile)
		if err != nil {
			return result, err
		}
	}

	transaction, err := beginTransaction(options.Root, manifest.Version, options.Now())
	if err != nil {
		return result, err
	}
	result.TransactionID = transaction.record.ID
	fail := func(cause error) (ApplyResult, error) {
		rollbackErr := rollbackInstallation(ctx, options.Root, options.Runner, transaction.record, transaction.journalPath)
		result.Status = "rolled_back"
		return result, errors.Join(cause, rollbackErr)
	}

	services := []string{"my-safe-agent.service"}
	if inspection.Plan.GatewayEnabled {
		services = append(services, "my-safe-gateway.service")
	}
	for _, service := range services {
		if err := transaction.RecordService(captureService(ctx, options.Runner, service)); err != nil {
			return fail(err)
		}
	}
	if err := ensureAccount(ctx, options.Runner, transaction, "my-safe", "/var/lib/my-safe"); err != nil {
		return fail(err)
	}
	if inspection.Plan.GatewayEnabled {
		if err := ensureAccount(ctx, options.Runner, transaction, "my-safe-gateway", "/nonexistent"); err != nil {
			return fail(err)
		}
	}
	if err := ensureDirectory(options.Root, "/etc/my-safe", 0o750); err != nil {
		return fail(err)
	}
	if err := ensureDirectory(options.Root, "/var/lib/my-safe", 0o700); err != nil {
		return fail(err)
	}

	agentArtifact, err := releasebundle.Select(manifest, "agent", "linux", inspection.Environment.Architecture)
	if err != nil {
		return fail(err)
	}
	agentBinary, err := os.ReadFile(filepath.Join(options.BundleDirectory, agentArtifact.Name))
	if err != nil {
		return fail(err)
	}
	agentUnit, err := installassets.AgentUnit()
	if err != nil {
		return fail(err)
	}
	publicKeyPEM, err := installassets.ReleasePublicKey()
	if err != nil {
		return fail(err)
	}
	embeddedKey, parseErr := releasebundle.ParsePublicKey(publicKeyPEM)
	if parseErr != nil {
		return fail(parseErr)
	}
	if !publicKey.Equal(embeddedKey) {
		// Tests may inject an ephemeral release key. Production always pins the
		// embedded key and installs that exact public material for updates.
		publicKeyPEM = nil
	}
	installFiles := []struct {
		path    string
		content []byte
		mode    os.FileMode
	}{
		{"/usr/local/bin/mysafe-agent", agentBinary, 0o755},
		{"/etc/systemd/system/my-safe-agent.service", agentUnit, 0o644},
		{"/etc/my-safe/agent.env", []byte(agentEnvironment(options.ControlURL)), 0o640},
	}
	installedState, err := jsonMarshal(installedRelease{
		Version: manifest.Version, InstalledAt: options.Now().UTC(), TransactionID: transaction.record.ID,
	})
	if err != nil {
		return fail(err)
	}
	installFiles = append(installFiles, struct {
		path    string
		content []byte
		mode    os.FileMode
	}{installedReleasePath, installedState, 0o600})
	if publicKeyPEM != nil {
		installFiles = append(installFiles, struct {
			path    string
			content []byte
			mode    os.FileMode
		}{"/etc/my-safe/release-public-key.pem", publicKeyPEM, 0o644})
	}
	if inspection.Plan.GatewayEnabled {
		gatewayArtifact, selectErr := releasebundle.Select(manifest, "gateway", "linux", inspection.Environment.Architecture)
		if selectErr != nil {
			return fail(selectErr)
		}
		gatewayBinary, readErr := os.ReadFile(filepath.Join(options.BundleDirectory, gatewayArtifact.Name))
		if readErr != nil {
			return fail(readErr)
		}
		gatewayUnit, assetErr := installassets.GatewayUnit()
		if assetErr != nil {
			return fail(assetErr)
		}
		installFiles = append(installFiles,
			struct {
				path    string
				content []byte
				mode    os.FileMode
			}{"/usr/local/bin/mysafe-gateway", gatewayBinary, 0o755},
			struct {
				path    string
				content []byte
				mode    os.FileMode
			}{"/etc/systemd/system/my-safe-gateway.service", gatewayUnit, 0o644},
			struct {
				path    string
				content []byte
				mode    os.FileMode
			}{"/etc/my-safe/gateway.env", []byte(gatewayEnvironment(inspection.Plan)), 0o640},
		)
	}
	for _, file := range installFiles {
		if err := transaction.InstallBytes(file.path, file.content, file.mode); err != nil {
			return fail(err)
		}
	}
	if err := runFixed(ctx, options.Runner, "chown", "-R", "my-safe:my-safe", rootPath(options.Root, "/var/lib/my-safe")); err != nil {
		return fail(err)
	}
	if err := runFixed(ctx, options.Runner, "chown", "root:my-safe", rootPath(options.Root, "/etc/my-safe/agent.env")); err != nil {
		return fail(err)
	}
	if inspection.Plan.GatewayEnabled {
		if err := runFixed(ctx, options.Runner, "chown", "root:my-safe-gateway", rootPath(options.Root, "/etc/my-safe/gateway.env")); err != nil {
			return fail(err)
		}
	}
	if err := runFixed(ctx, options.Runner, "systemctl", "daemon-reload"); err != nil {
		return fail(err)
	}
	if !options.SkipRegistration {
		environment := []string{
			"MYSAFE_CONTROL_URL=" + options.ControlURL,
			"MYSAFE_STATE_DIR=" + rootPath(options.Root, "/var/lib/my-safe"),
			"MYSAFE_BOOTSTRAP_TOKEN=" + bootstrapToken,
		}
		if _, err := options.Runner.RunEnv(ctx, environment, "runuser", "-u", "my-safe", "--", rootPath(options.Root, "/usr/local/bin/mysafe-agent"), "--once"); err != nil {
			return fail(fmt.Errorf("register Agent: %w", err))
		}
		bootstrapToken = ""
	}
	if err := runFixed(ctx, options.Runner, "systemctl", "enable", "--now", "my-safe-agent.service"); err != nil {
		return fail(err)
	}
	if inspection.Plan.GatewayEnabled {
		if err := runFixed(ctx, options.Runner, "systemctl", "enable", "--now", "my-safe-gateway.service"); err != nil {
			return fail(err)
		}
		if !options.SkipHealthCheck {
			if err := waitForGateway(ctx, inspection.Plan.GatewayListen); err != nil {
				return fail(err)
			}
		}
		if err := applyNginxGateway(ctx, options.Root, options.Runner, transaction, inspection.Plan); err != nil {
			return fail(err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return fail(err)
	}
	result.Status = "complete"
	return result, nil
}

func RollbackLatest(ctx context.Context, root string, runner ApplyRunner) (TransactionRecord, error) {
	if root == "" {
		root = string(filepath.Separator)
	}
	resolvedRoot, err := filepath.Abs(root)
	if err != nil {
		return TransactionRecord{}, err
	}
	if runner == nil {
		runner = OSRunner{}
	}
	record, journalPath, err := loadLatestTransaction(resolvedRoot)
	if err != nil {
		return TransactionRecord{}, err
	}
	if record.Status != "complete" && record.Status != "applying" {
		return record, fmt.Errorf("latest transaction status is %s", record.Status)
	}
	if err := rollbackInstallation(ctx, resolvedRoot, runner, record, journalPath); err != nil {
		return record, err
	}
	record.Status = "rolled_back"
	return record, nil
}

func normalizeApplyOptions(options ApplyOptions) ApplyOptions {
	if options.Root == "" {
		options.Root = string(filepath.Separator)
	}
	options.Root, _ = filepath.Abs(options.Root)
	if options.BundleDirectory == "" {
		options.BundleDirectory = "."
	}
	options.BundleDirectory, _ = filepath.Abs(options.BundleDirectory)
	if options.ManifestPath == "" {
		options.ManifestPath = filepath.Join(options.BundleDirectory, "release-manifest.json")
	}
	if options.SignaturePath == "" {
		options.SignaturePath = filepath.Join(options.BundleDirectory, "release-manifest.sig")
	}
	if options.Architecture == "" {
		options.Architecture = runtime.GOARCH
	}
	if options.Gateway == "" {
		options.Gateway = GatewayAuto
	}
	if options.Runner == nil {
		options.Runner = OSRunner{}
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return options
}

func verifyRelease(options ApplyOptions) ([]byte, []byte, ed25519.PublicKey, releasebundle.Manifest, error) {
	manifestBytes, err := os.ReadFile(options.ManifestPath)
	if err != nil {
		return nil, nil, nil, releasebundle.Manifest{}, fmt.Errorf("read release manifest: %w", err)
	}
	signature, err := os.ReadFile(options.SignaturePath)
	if err != nil {
		return nil, nil, nil, releasebundle.Manifest{}, fmt.Errorf("read release signature: %w", err)
	}
	publicKey := options.PublicKey
	if len(publicKey) == 0 {
		encoded, err := installassets.ReleasePublicKey()
		if err != nil {
			return nil, nil, nil, releasebundle.Manifest{}, err
		}
		publicKey, err = releasebundle.ParsePublicKey(encoded)
		if err != nil {
			return nil, nil, nil, releasebundle.Manifest{}, err
		}
	}
	if err := releasebundle.VerifySignature(manifestBytes, signature, publicKey); err != nil {
		return nil, nil, nil, releasebundle.Manifest{}, err
	}
	manifest, err := releasebundle.Decode(manifestBytes)
	if err != nil {
		return nil, nil, nil, releasebundle.Manifest{}, err
	}
	options.PublicKey = publicKey
	return manifestBytes, signature, publicKey, manifest, nil
}

func ensureAccount(ctx context.Context, runner ApplyRunner, transaction *fileTransaction, name, home string) error {
	if _, err := runner.Run(ctx, "getent", "group", name); err != nil {
		if err := runFixed(ctx, runner, "groupadd", "--system", name); err != nil {
			return err
		}
		if err := transaction.RecordCreatedGroup(name); err != nil {
			return err
		}
	}
	if _, err := runner.Run(ctx, "id", name); err != nil {
		if err := runFixed(ctx, runner, "useradd", "--system", "--gid", name, "--home-dir", home, "--shell", "/usr/sbin/nologin", name); err != nil {
			return err
		}
		if err := transaction.RecordCreatedUser(name); err != nil {
			return err
		}
	}
	return nil
}

func captureService(ctx context.Context, runner ApplyRunner, name string) ServiceChange {
	_, enabledErr := runner.Run(ctx, "systemctl", "is-enabled", name)
	_, activeErr := runner.Run(ctx, "systemctl", "is-active", name)
	return ServiceChange{Name: name, WasEnabled: enabledErr == nil, WasActive: activeErr == nil}
}

func rollbackInstallation(ctx context.Context, root string, runner ApplyRunner, record TransactionRecord, journalPath string) error {
	var rollbackErrors []error
	for index := len(record.Services) - 1; index >= 0; index-- {
		if err := runFixed(ctx, runner, "systemctl", "disable", "--now", record.Services[index].Name); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	if err := rollbackChanges(root, record); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if err := runFixed(ctx, runner, "systemctl", "daemon-reload"); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	if record.NginxChanged {
		if err := runFixed(ctx, runner, "nginx", "-t"); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		} else if err := runFixed(ctx, runner, "systemctl", "reload", "nginx.service"); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	for _, service := range record.Services {
		if service.WasEnabled {
			if err := runFixed(ctx, runner, "systemctl", "enable", service.Name); err != nil {
				rollbackErrors = append(rollbackErrors, err)
			}
		}
		if service.WasActive {
			if err := runFixed(ctx, runner, "systemctl", "start", service.Name); err != nil {
				rollbackErrors = append(rollbackErrors, err)
			}
		}
	}
	for index := len(record.CreatedUsers) - 1; index >= 0; index-- {
		if err := runFixed(ctx, runner, "userdel", record.CreatedUsers[index]); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	for index := len(record.CreatedGroups) - 1; index >= 0; index-- {
		if err := runFixed(ctx, runner, "groupdel", record.CreatedGroups[index]); err != nil {
			rollbackErrors = append(rollbackErrors, err)
		}
	}
	record.Status = "rolled_back"
	encoded, err := jsonMarshal(record)
	if err != nil {
		rollbackErrors = append(rollbackErrors, err)
	} else if err := writeAtomic(journalPath, encoded, 0o600); err != nil {
		rollbackErrors = append(rollbackErrors, err)
	}
	return errors.Join(rollbackErrors...)
}

func ensureDirectory(root, unixPath string, mode os.FileMode) error {
	path := rootPath(root, unixPath)
	if !withinRoot(root, path) {
		return fmt.Errorf("directory escapes root: %s", unixPath)
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("create %s: %w", unixPath, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("chmod %s: %w", unixPath, err)
	}
	return nil
}

func validateControlURL(raw string) error {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("control URL must be an absolute HTTP(S) URL")
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return errors.New("control URL scheme must be http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || strings.ContainsAny(raw, "\r\n\x00") {
		return errors.New("control URL must not contain credentials, query, fragment, or control characters")
	}
	if parsed.Scheme == "http" && !loopbackHost(parsed.Hostname()) {
		return errors.New("plain HTTP control URL is only allowed on loopback")
	}
	return nil
}

func readBootstrapToken(path string) (string, error) {
	if path == "" {
		return "", errors.New("bootstrap token file is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("stat bootstrap token file: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() > 4096 {
		return "", errors.New("bootstrap token file must be a regular file no larger than 4 KiB")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read bootstrap token file: %w", err)
	}
	token := strings.TrimSpace(string(encoded))
	if len(token) < 16 || strings.ContainsAny(token, "\r\n\x00") {
		return "", errors.New("bootstrap token must be one line containing at least 16 bytes")
	}
	return token, nil
}

func agentEnvironment(controlURL string) string {
	return "MYSAFE_CONTROL_URL=" + strconv.Quote(controlURL) +
		"\nMYSAFE_STATE_DIR=/var/lib/my-safe" +
		"\nMYSAFE_GATEWAY_EVENT_SOCKET=/run/my-safe/gateway-events.sock\n"
}

func gatewayEnvironment(plan Plan) string {
	return "MYSAFE_GATEWAY_ADDRESS=" + strconv.Quote(plan.GatewayListen) +
		"\nMYSAFE_GATEWAY_UPSTREAM=" + strconv.Quote(plan.Upstream) +
		"\nMYSAFE_GATEWAY_MODE=observe" +
		"\nMYSAFE_GATEWAY_FAILURE_POLICY=fail_open" +
		"\nMYSAFE_GATEWAY_EVENT_SOCKET=/run/my-safe/gateway-events.sock" +
		"\nMYSAFE_GATEWAY_STATE_DIR=/var/lib/my-safe-gateway\n"
}

func runFixed(ctx context.Context, runner ApplyRunner, name string, arguments ...string) error {
	if _, err := runner.Run(ctx, name, arguments...); err != nil {
		return fmt.Errorf("%s failed: %w", name, err)
	}
	return nil
}

func waitForGateway(ctx context.Context, listen string) error {
	client := &http.Client{Timeout: time.Second}
	endpoint := "http://" + listen + "/__mysafe/healthz"
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err == nil {
			response, requestErr := client.Do(request)
			if requestErr == nil {
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("Gateway health check timed out")
		case <-ticker.C:
		}
	}
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	address := net.ParseIP(host)
	return address != nil && address.IsLoopback()
}

func samePath(left, right string) bool {
	leftPath, leftErr := filepath.Abs(left)
	rightPath, rightErr := filepath.Abs(right)
	return leftErr == nil && rightErr == nil && leftPath == rightPath
}

func jsonMarshal(value any) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}
