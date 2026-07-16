package installer

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/releasebundle"
)

type recordingRunner struct {
	calls   []string
	failKey string
}

func (runner *recordingRunner) LookPath(name string) (string, error) {
	if name == "systemctl" || name == "nginx" {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (runner *recordingRunner) Run(_ context.Context, name string, arguments ...string) (string, error) {
	key := name + " " + strings.Join(arguments, " ")
	runner.calls = append(runner.calls, key)
	if key == runner.failKey {
		return "", errors.New("injected command failure")
	}
	switch key {
	case "systemctl --version":
		return "systemd 255\n", nil
	case "nginx -v":
		return "nginx version: nginx/1.24.0\n", nil
	}
	if strings.HasPrefix(key, "getent group ") || strings.HasPrefix(key, "id ") || strings.HasPrefix(key, "systemctl is-enabled ") || strings.HasPrefix(key, "systemctl is-active ") {
		return "", errors.New("not found")
	}
	return "", nil
}

func (runner *recordingRunner) RunEnv(_ context.Context, _ []string, name string, arguments ...string) (string, error) {
	key := name + " " + strings.Join(arguments, " ")
	runner.calls = append(runner.calls, key)
	if key == runner.failKey {
		return "", errors.New("injected command failure")
	}
	return "", nil
}

func TestApplyAndExplicitRollback(t *testing.T) {
	root := installFixture(t)
	bundle, publicKey := signedTestBundle(t)
	token := "one-time-bootstrap-token-never-store"
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{}
	result, err := Apply(context.Background(), ApplyOptions{
		Root:               root,
		BundleDirectory:    bundle,
		ControlURL:         "http://127.0.0.1:8080",
		BootstrapTokenFile: tokenPath,
		Architecture:       "amd64",
		Runner:             runner,
		PublicKey:          publicKey,
		SkipHealthCheck:    true,
		Now: func() time.Time {
			return time.Date(2026, 7, 16, 9, 0, 0, 0, time.UTC)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "complete" || !result.Inspection.Plan.GatewayEnabled || result.TransactionID == "" {
		t.Fatalf("Apply() = %#v", result)
	}
	assertFileContent(t, root, "/usr/local/bin/mysafe-agent", "new-agent")
	assertFileContent(t, root, "/usr/local/bin/mysafe-gateway", "new-gateway")
	nginxConfig := rootPath(root, "/etc/nginx/conf.d/app.conf")
	updatedNginx, err := os.ReadFile(nginxConfig)
	if err != nil || !strings.Contains(string(updatedNginx), "proxy_pass http://127.0.0.1:18081;") {
		t.Fatalf("Nginx was not connected to Gateway: %s, %v", updatedNginx, err)
	}
	if found := findTextInRoot(t, root, token); found != "" {
		t.Fatalf("bootstrap token persisted in %s", found)
	}
	installed, exists, err := loadInstalledRelease(root)
	if err != nil || !exists || installed.Version != "v0.2.0-test" || installed.TransactionID != result.TransactionID {
		t.Fatalf("installed release = %#v, %t, %v", installed, exists, err)
	}
	record, _, err := loadLatestTransaction(root)
	if err != nil || record.Status != "complete" {
		t.Fatalf("journal = %#v, %v", record, err)
	}

	rolledBack, err := RollbackLatest(context.Background(), root, runner)
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Status != "rolled_back" {
		t.Fatalf("rollback record = %#v", rolledBack)
	}
	if _, err := os.Stat(rootPath(root, "/usr/local/bin/mysafe-agent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new Agent binary remains after rollback: %v", err)
	}
	if _, exists, err := loadInstalledRelease(root); err != nil || exists {
		t.Fatalf("installed release remains after rollback: exists=%t err=%v", exists, err)
	}
	restoredNginx, err := os.ReadFile(nginxConfig)
	if err != nil || !strings.Contains(string(restoredNginx), "proxy_pass http://127.0.0.1:3000;") {
		t.Fatalf("Nginx was not restored: %s, %v", restoredNginx, err)
	}
}

func TestNginxValidationFailureRollsBackTrafficConfiguration(t *testing.T) {
	root := installFixture(t)
	bundle, publicKey := signedTestBundle(t)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("one-time-bootstrap-token-never-store\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{failKey: "nginx -t"}
	result, err := Apply(context.Background(), ApplyOptions{
		Root: root, BundleDirectory: bundle, ControlURL: "http://127.0.0.1:8080",
		BootstrapTokenFile: tokenPath, Architecture: "amd64", Runner: runner,
		PublicKey: publicKey, SkipHealthCheck: true,
	})
	if err == nil || result.Status != "rolled_back" {
		t.Fatalf("Apply() result = %#v, error = %v", result, err)
	}
	content, readErr := os.ReadFile(rootPath(root, "/etc/nginx/conf.d/app.conf"))
	if readErr != nil || !strings.Contains(string(content), "proxy_pass http://127.0.0.1:3000;") {
		t.Fatalf("Nginx configuration not restored: %s, %v", content, readErr)
	}
}

func TestApplyFailureRestoresPreviousFiles(t *testing.T) {
	root := installFixture(t)
	oldPath := rootPath(root, "/usr/local/bin/mysafe-agent")
	if err := os.MkdirAll(filepath.Dir(oldPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldPath, []byte("old-agent"), 0o700); err != nil {
		t.Fatal(err)
	}
	bundle, publicKey := signedTestBundle(t)
	tokenPath := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tokenPath, []byte("one-time-bootstrap-token-never-store\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &recordingRunner{failKey: "systemctl enable --now my-safe-gateway.service"}
	result, err := Apply(context.Background(), ApplyOptions{
		Root: root, BundleDirectory: bundle, ControlURL: "http://127.0.0.1:8080",
		BootstrapTokenFile: tokenPath, Architecture: "amd64", Runner: runner,
		PublicKey: publicKey, SkipHealthCheck: true,
	})
	if err == nil || result.Status != "rolled_back" {
		t.Fatalf("Apply() result = %#v, error = %v", result, err)
	}
	assertFileContent(t, root, "/usr/local/bin/mysafe-agent", "old-agent")
	if _, err := os.Stat(rootPath(root, "/usr/local/bin/mysafe-gateway")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("Gateway remains after failed install: %v", err)
	}
	record, _, err := loadLatestTransaction(root)
	if err != nil || record.Status != "rolled_back" {
		t.Fatalf("rollback journal = %#v, %v", record, err)
	}
}

func TestTamperedBundleIsRejectedBeforeTransaction(t *testing.T) {
	root := installFixture(t)
	bundle, publicKey := signedTestBundle(t)
	if err := os.WriteFile(filepath.Join(bundle, "mysafe-agent-linux-amd64"), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Apply(context.Background(), ApplyOptions{
		Root: root, BundleDirectory: bundle, ControlURL: "http://127.0.0.1:8080",
		Architecture: "amd64", Runner: &recordingRunner{}, PublicKey: publicKey,
		SkipRegistration: true, SkipHealthCheck: true,
	})
	if err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered bundle error = %v", err)
	}
	if _, statErr := os.Stat(rootPath(root, transactionDirectory)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("transaction started for tampered bundle: %v", statErr)
	}
}

func TestUnexpectedReleaseVersionIsRejectedBeforeInspectionOrTransaction(t *testing.T) {
	root := installFixture(t)
	bundle, publicKey := signedTestBundle(t)
	runner := &recordingRunner{}
	_, err := Apply(context.Background(), ApplyOptions{
		Root: root, BundleDirectory: bundle, ExpectedVersion: "v0.2.1-test",
		ControlURL: "http://127.0.0.1:8080", Architecture: "amd64",
		Runner: runner, PublicKey: publicKey, SkipRegistration: true,
	})
	if err == nil || !strings.Contains(err.Error(), "does not match requested version") {
		t.Fatalf("version mismatch error = %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("environment inspected before version rejection: %v", runner.calls)
	}
	if _, statErr := os.Stat(rootPath(root, transactionDirectory)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("transaction started for wrong release version: %v", statErr)
	}
}

func TestSignedDowngradeRequiresExplicitOverride(t *testing.T) {
	root := installFixture(t)
	statePath := rootPath(root, installedReleasePath)
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, err := jsonMarshal(installedRelease{
		Version: "v0.3.0", InstalledAt: time.Now().UTC(), TransactionID: "existing_transaction",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	bundle, publicKey := signedTestBundle(t)
	_, err = Apply(context.Background(), ApplyOptions{
		Root: root, BundleDirectory: bundle, ControlURL: "http://127.0.0.1:8080",
		Architecture: "amd64", Runner: &recordingRunner{}, PublicKey: publicKey,
		SkipRegistration: true, SkipHealthCheck: true,
	})
	if err == nil || !strings.Contains(err.Error(), "refusing downgrade") {
		t.Fatalf("downgrade error = %v", err)
	}
	if _, statErr := os.Stat(rootPath(root, transactionDirectory)); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("transaction started for refused downgrade: %v", statErr)
	}
}

func installFixture(t *testing.T) string {
	t.Helper()
	return fixtureRoot(t, "ID=ubuntu\nVERSION_ID=\"24.04\"\nVERSION_CODENAME=noble\n", `server {
  location / {
    proxy_pass http://127.0.0.1:3000;
  }
}`)
}

func signedTestBundle(t *testing.T) (string, ed25519.PublicKey) {
	t.Helper()
	directory := t.TempDir()
	writeBundleArtifact(t, directory, "mysafe-agent-linux-amd64", "new-agent")
	writeBundleArtifact(t, directory, "mysafe-gateway-linux-amd64", "new-gateway")
	manifest, err := releasebundle.Build(directory, "v0.2.0-test", time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := releasebundle.Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "release-manifest.json"), encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "release-manifest.sig"), []byte(releasebundle.Sign(encoded, privateKey)), 0o644); err != nil {
		t.Fatal(err)
	}
	return directory, publicKey
}

func writeBundleArtifact(t *testing.T, directory, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func assertFileContent(t *testing.T, root, unixPath, want string) {
	t.Helper()
	content, err := os.ReadFile(rootPath(root, unixPath))
	if err != nil || string(content) != want {
		t.Fatalf("%s = %q, %v; want %q", unixPath, content, err, want)
	}
}

func findTextInRoot(t *testing.T, root, needle string) string {
	t.Helper()
	found := ""
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return err
		}
		content, readErr := os.ReadFile(path)
		if readErr == nil && strings.Contains(string(content), needle) {
			found = path
			return fmt.Errorf("found")
		}
		return nil
	})
	if err != nil && found == "" {
		t.Fatal(err)
	}
	return found
}
