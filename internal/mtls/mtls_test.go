package mtls

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCSRSigningPersistenceAndAgentIdentity(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 16, 0, 0, 0, time.UTC)
	issuerDir := t.TempDir()
	issuer, err := LoadOrCreateIssuer(issuerDir, now)
	if err != nil {
		t.Fatal(err)
	}
	agentDir := t.TempDir()
	csr, err := EnsureClientCSR(agentDir, "mch_test_machine")
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, err := issuer.Issue(csr, "agt_test_agent", "mch_test_machine", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveClientCertificate(agentDir, "agt_test_agent", certificatePEM, now); err != nil {
		t.Fatal(err)
	}
	clientCertificate, exists, err := LoadClientCertificate(agentDir, now)
	if err != nil || !exists || clientCertificate.Leaf == nil {
		t.Fatalf("LoadClientCertificate() = %#v, %t, %v", clientCertificate, exists, err)
	}
	if !MatchesAgent(clientCertificate.Leaf, "agt_test_agent") || MatchesAgent(clientCertificate.Leaf, "agt_other") {
		t.Fatalf("issued identity = %#v", clientCertificate.Leaf.URIs)
	}
	if _, err := clientCertificate.Leaf.Verify(x509.VerifyOptions{Roots: issuer.CertPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("verify client certificate: %v", err)
	}
	httpClient, err := HTTPClientWithCertificate(&http.Client{Timeout: time.Second}, clientCertificate)
	if err != nil || httpClient.Transport == nil {
		t.Fatalf("HTTPClientWithCertificate() = %#v, %v", httpClient, err)
	}

	reloaded, err := LoadOrCreateIssuer(issuerDir, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	firstFingerprint := sha256.Sum256(issuer.CertificatePEM())
	secondFingerprint := sha256.Sum256(reloaded.CertificatePEM())
	if firstFingerprint != secondFingerprint {
		t.Fatal("Agent CA changed after reload")
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{filepath.Join(issuerDir, caPrivateKeyFilename), filepath.Join(agentDir, clientPrivateFilename), filepath.Join(agentDir, clientCertFilename)} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm()&0o077 != 0 {
				t.Fatalf("private mTLS file %s mode = %v", path, info.Mode().Perm())
			}
		}
	}
}

func TestIssuerRejectsMismatchedCSRMachineIdentity(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	issuer, err := LoadOrCreateIssuer(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := EnsureClientCSR(t.TempDir(), "mch_one")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := issuer.Issue(csr, "agt_one", "mch_two", now); err == nil {
		t.Fatal("issuer signed a CSR for the wrong machine identity")
	}
}

func TestSaveRejectsCertificateForDifferentAgent(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	issuer, err := LoadOrCreateIssuer(t.TempDir(), now)
	if err != nil {
		t.Fatal(err)
	}
	agentDir := t.TempDir()
	csr, err := EnsureClientCSR(agentDir, "mch_one")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := issuer.Issue(csr, "agt_one", "mch_one", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveClientCertificate(agentDir, "agt_two", encoded, now); err == nil {
		t.Fatal("saved a certificate with the wrong Agent SAN")
	}
	block, _ := pem.Decode(encoded)
	if block == nil {
		t.Fatal("issued certificate is not PEM")
	}
}
