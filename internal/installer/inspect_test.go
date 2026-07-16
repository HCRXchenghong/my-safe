package installer

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeRunner struct {
	available map[string]bool
	outputs   map[string]string
}

func (runner fakeRunner) LookPath(name string) (string, error) {
	if runner.available[name] {
		return "/usr/bin/" + name, nil
	}
	return "", errors.New("not found")
}

func (runner fakeRunner) Run(_ context.Context, name string, arguments ...string) (string, error) {
	key := name + " " + strings.Join(arguments, " ")
	return runner.outputs[key], nil
}

func TestInspectBuildsDeterministicNginxGatewayPlan(t *testing.T) {
	t.Parallel()
	root := fixtureRoot(t, `ID=ubuntu
VERSION_ID="24.04"
VERSION_CODENAME=noble
`, `server {
  listen 443 ssl;
  location / { proxy_pass http://127.0.0.1:3000; }
}`)
	writeFixture(t, root, "proc/net/tcp", "  sl local_address rem_address st\n  0: 0100007F:46A1 00000000:0000 0A\n")
	runner := fakeRunner{
		available: map[string]bool{"systemctl": true, "nginx": true, "docker": true},
		outputs: map[string]string{
			"systemctl --version": "systemd 255\n",
			"nginx -v":            "nginx version: nginx/1.24.0\n",
			"docker version --format {{.Server.Version}}": "29.6.1\n",
			"docker compose version --short":              "2.39.0\n",
		},
	}
	got, err := Inspect(context.Background(), InspectOptions{Root: root, Architecture: "x86_64", Runner: runner})
	if err != nil {
		t.Fatal(err)
	}
	if got.Environment.Support != SupportStable || got.Environment.Architecture != "amd64" {
		t.Fatalf("environment = %#v", got.Environment)
	}
	if !got.Plan.Installable || !got.Plan.GatewayEnabled || got.Plan.Upstream != "http://127.0.0.1:3000" {
		t.Fatalf("plan = %#v", got.Plan)
	}
	if got.Plan.GatewayListen != "127.0.0.1:18082" {
		t.Fatalf("gateway listen = %q, want next free port", got.Plan.GatewayListen)
	}
	if got.Plan.NginxConfig != "/etc/nginx/conf.d/app.conf" {
		t.Fatalf("nginx config = %q", got.Plan.NginxConfig)
	}
}

func TestAmbiguousNginxStaysInSensorMode(t *testing.T) {
	t.Parallel()
	root := fixtureRoot(t, "ID=debian\nVERSION_ID=13\n", `server {
  location /one { proxy_pass http://127.0.0.1:3000; }
  location /two { proxy_pass http://127.0.0.1:4000; }
}`)
	inspection, err := Inspect(context.Background(), InspectOptions{
		Root: root, Architecture: "arm64",
		Runner: fakeRunner{available: map[string]bool{"systemctl": true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.Plan.Installable || inspection.Plan.GatewayEnabled || inspection.Plan.Integration != "sensor" {
		t.Fatalf("ambiguous plan = %#v", inspection.Plan)
	}
	if len(inspection.Plan.Notices) == 0 || !strings.Contains(inspection.Plan.Notices[0], "multiple") {
		t.Fatalf("notices = %#v", inspection.Plan.Notices)
	}
}

func TestUnsupportedPlatformIsNotInstallable(t *testing.T) {
	t.Parallel()
	root := fixtureRoot(t, "ID=alpine\nVERSION_ID=3.22\n", "")
	inspection, err := Inspect(context.Background(), InspectOptions{
		Root: root, Architecture: "amd64",
		Runner: fakeRunner{available: map[string]bool{"systemctl": true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Plan.Installable || inspection.Environment.Support != SupportUnsupported || len(inspection.Plan.Blockers) == 0 {
		t.Fatalf("unsupported inspection = %#v", inspection)
	}
}

func TestExplicitGatewayRequiresValidUpstream(t *testing.T) {
	t.Parallel()
	environment := Environment{OSID: "ubuntu", OSVersion: "24.04", Architecture: "amd64", Support: SupportStable, Systemd: Tool{Available: true}}
	plan := BuildPlan(environment, PlanOptions{Gateway: GatewayEnabled, Upstream: "file:///etc/passwd"})
	if plan.Installable || len(plan.Blockers) == 0 {
		t.Fatalf("plan = %#v", plan)
	}
}

func TestListeningPortParser(t *testing.T) {
	t.Parallel()
	content := []byte("  sl local_address rem_address st\n  0: 0100007F:46A1 00000000:0000 0A\n  1: 0100007F:0BB8 00000000:0000 0A\n")
	if got, want := parseListeningPorts(content), []int{3000, 18081}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ports = %#v, want %#v", got, want)
	}
}

func fixtureRoot(t *testing.T, osRelease, nginx string) string {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "etc/os-release", osRelease)
	if nginx != "" {
		writeFixture(t, root, "etc/nginx/conf.d/app.conf", nginx)
	}
	return root
}

func writeFixture(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
