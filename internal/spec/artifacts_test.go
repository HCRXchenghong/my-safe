package spec_test

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/HCRXchenghong/my-safe/internal/installassets"
	"go.yaml.in/yaml/v3"
	"mvdan.cc/sh/v3/syntax"
)

func TestYAMLArtifactsParse(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	paths := []string{
		"api/openapi.yaml",
		"deploy/compose.yaml",
		".github/workflows/ci.yml",
		".github/workflows/release.yml",
	}
	for _, relative := range paths {
		relative := relative
		t.Run(relative, func(t *testing.T) {
			t.Parallel()
			content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
			if err != nil {
				t.Fatal(err)
			}
			var document any
			if err := yaml.Unmarshal(content, &document); err != nil {
				t.Fatalf("invalid YAML: %v", err)
			}
		})
	}
}

func TestBootstrapPinnedReleaseKeyMatchesDeployFile(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	script, err := os.ReadFile(filepath.Join(root, "scripts", "bootstrap.sh"))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := os.ReadFile(filepath.Join(root, "deploy", "release-public-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(script, bytes.TrimSpace(publicKey)) {
		t.Fatal("bootstrap.sh does not pin deploy/release-public-key.pem")
	}
}

func TestEmbeddedInstallerAssetsMatchDeployFiles(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	tests := []struct {
		path string
		load func() ([]byte, error)
	}{
		{"deploy/systemd/my-safe-agent.service", installassets.AgentUnit},
		{"deploy/systemd/my-safe-gateway.service", installassets.GatewayUnit},
		{"deploy/release-public-key.pem", installassets.ReleasePublicKey},
	}
	for _, test := range tests {
		disk, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(test.path)))
		if err != nil {
			t.Fatal(err)
		}
		embedded, err := test.load()
		if err != nil {
			t.Fatal(err)
		}
		if string(disk) != string(embedded) {
			t.Errorf("embedded installer asset differs from %s", test.path)
		}
	}
}

func TestBashArtifactsParse(t *testing.T) {
	t.Parallel()
	root := repositoryRoot(t)
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	for _, relative := range []string{"scripts/build.sh", "scripts/package-deb.sh", "scripts/install-agent.sh", "scripts/bootstrap.sh"} {
		path := filepath.Join(root, filepath.FromSlash(relative))
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		_, parseErr := parser.Parse(file, relative)
		closeErr := file.Close()
		if parseErr != nil {
			t.Errorf("%s has invalid Bash syntax: %v", relative, parseErr)
		}
		if closeErr != nil {
			t.Errorf("close %s: %v", relative, closeErr)
		}
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot resolve test source path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
}
