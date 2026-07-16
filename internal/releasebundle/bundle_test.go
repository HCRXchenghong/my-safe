package releasebundle

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSignedManifestAndArtifactVerification(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	writeArtifact(t, directory, "mysafe-agent-linux-amd64", "agent-binary")
	writeArtifact(t, directory, "mysafe-gateway-linux-amd64", "gateway-binary")
	writeArtifact(t, directory, "mysafe-agent-linux-amd64.deb", "agent-package")
	manifest, err := Build(directory, "v0.2.0", time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := []byte(Sign(encoded, privateKey))
	if err := VerifySignature(encoded, signature, publicKey); err != nil {
		t.Fatal(err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifacts(directory, decoded); err != nil {
		t.Fatal(err)
	}
	selected, err := Select(decoded, "agent", "linux", "amd64")
	if err != nil || selected.Name != "mysafe-agent-linux-amd64" {
		t.Fatalf("Select() = %#v, %v", selected, err)
	}
	selectedPackage, err := SelectFormat(decoded, "agent", "linux", "amd64", "deb")
	if err != nil || selectedPackage.Name != "mysafe-agent-linux-amd64.deb" || selectedPackage.Mode != 0o644 {
		t.Fatalf("SelectFormat() = %#v, %v", selectedPackage, err)
	}

	if err := os.WriteFile(filepath.Join(directory, selected.Name), []byte("tampered"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := VerifyArtifacts(directory, decoded); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("tampered artifact error = %v", err)
	}
}

func TestSignatureRejectsManifestTampering(t *testing.T) {
	t.Parallel()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := []byte("trusted manifest")
	signature := []byte(Sign(manifest, privateKey))
	if err := VerifySignature([]byte("tampered manifest"), signature, publicKey); err == nil {
		t.Fatal("tampered manifest passed signature verification")
	}
}

func TestVerifySelectionAllowsPartialArchitectureBundle(t *testing.T) {
	t.Parallel()
	full := t.TempDir()
	writeArtifact(t, full, "mysafe-agent-linux-amd64", "amd64-agent")
	writeArtifact(t, full, "mysafe-agent-linux-arm64", "arm64-agent")
	manifest, err := Build(full, "v0.3.0", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	partial := t.TempDir()
	writeArtifact(t, partial, "mysafe-agent-linux-amd64", "amd64-agent")
	if err := VerifySelection(partial, manifest, "linux", "amd64", "agent"); err != nil {
		t.Fatal(err)
	}
	if err := VerifySelection(partial, manifest, "linux", "arm64", "agent"); err == nil {
		t.Fatal("missing selected architecture passed verification")
	}
}

func TestManifestRejectsTraversalAndDuplicates(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	base := Artifact{Name: "mysafe-agent-linux-amd64", Component: "agent", OS: "linux", Arch: "amd64", SHA256: strings.Repeat("0", 64), Size: 1, Mode: 0o755, Format: "binary"}
	manifest := Manifest{SchemaVersion: SchemaVersion, Version: "v0.1.0", CreatedAt: now, Artifacts: []Artifact{base, base}}
	if err := Validate(manifest); err == nil {
		t.Fatal("duplicate artifact passed validation")
	}
	base.Name = "../mysafe-agent-linux-amd64"
	manifest.Artifacts = []Artifact{base}
	if err := Validate(manifest); err == nil {
		t.Fatal("traversal artifact passed validation")
	}
}

func TestGenerateAndLoadKeyFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.pem")
	publicPath := filepath.Join(directory, "public.pem")
	fingerprint, err := GenerateKeyFiles(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := LoadPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := LoadPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if fingerprint != PublicKeyFingerprint(publicKey) || !publicKey.Equal(privateKey.Public()) {
		t.Fatal("generated key files do not form a pair")
	}
	if _, err := GenerateKeyFiles(privatePath, publicPath); err == nil {
		t.Fatal("key generation overwrote existing files")
	}
}

func writeArtifact(t *testing.T, directory, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(directory, name), []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}
