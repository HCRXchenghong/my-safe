package mtls

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	caCertificateFilename = "agent-ca-cert.pem"
	caPrivateKeyFilename  = "agent-ca-key.pem"
	clientPrivateFilename = "agent-client-key.pem"
	clientCertFilename    = "agent-client-cert.pem"
	clientLifetime        = 30 * 24 * time.Hour
)

type Issuer struct {
	certificate *x509.Certificate
	privateKey  ed25519.PrivateKey
	encodedCert []byte
}

func LoadOrCreateIssuer(directory string, now time.Time) (*Issuer, error) {
	if strings.TrimSpace(directory) == "" {
		return nil, errors.New("Agent CA directory is required")
	}
	directory, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	certPath := filepath.Join(directory, caCertificateFilename)
	keyPath := filepath.Join(directory, caPrivateKeyFilename)
	certExists := regularFileExists(certPath)
	keyExists := regularFileExists(keyPath)
	if certExists != keyExists {
		return nil, errors.New("Agent CA certificate and private key must exist together")
	}
	if !certExists {
		if err := generateCA(certPath, keyPath, now.UTC()); err != nil {
			return nil, err
		}
	}
	return LoadIssuer(certPath, keyPath, now)
}

func LoadIssuer(certPath, keyPath string, now time.Time) (*Issuer, error) {
	certPEM, err := readRegular(certPath, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read Agent CA certificate: %w", err)
	}
	keyPEM, err := readRegular(keyPath, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("read Agent CA private key: %w", err)
	}
	certificate, err := parseCertificatePEM(certPEM)
	if err != nil {
		return nil, err
	}
	privateKey, err := parseEd25519PrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	if !certificate.IsCA || certificate.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) {
		return nil, errors.New("Agent CA certificate is not a currently valid signing CA")
	}
	if !publicKeysEqual(certificate.PublicKey, privateKey.Public()) {
		return nil, errors.New("Agent CA certificate does not match its private key")
	}
	return &Issuer{certificate: certificate, privateKey: privateKey, encodedCert: append([]byte(nil), certPEM...)}, nil
}

func (issuer *Issuer) Issue(csrPEM []byte, agentID, machineID string, now time.Time) ([]byte, error) {
	if !validIdentifier(agentID, 128) || !validIdentifier(machineID, 128) {
		return nil, errors.New("Agent and machine identifiers are required")
	}
	csr, err := parseCSR(csrPEM)
	if err != nil {
		return nil, err
	}
	if csr.Subject.CommonName != machineID {
		return nil, errors.New("CSR common name does not match machine identity")
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, errors.New("Agent CSR must use an Ed25519 key")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	identityURI := &url.URL{Scheme: "spiffe", Host: "my-safe", Path: "/agent/" + agentID}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: agentID, Organization: []string{"My Safe"}, OrganizationalUnit: []string{"Agent"}},
		NotBefore:             now.UTC().Add(-5 * time.Minute),
		NotAfter:              now.UTC().Add(clientLifetime),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs:                  []*url.URL{identityURI},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer.certificate, csr.PublicKey, issuer.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign Agent certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (issuer *Issuer) CertificatePEM() []byte {
	return append([]byte(nil), issuer.encodedCert...)
}

func (issuer *Issuer) CertPool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(issuer.certificate)
	return pool
}

func EnsureClientCSR(stateDir, machineID string) ([]byte, error) {
	if !validIdentifier(machineID, 128) {
		return nil, errors.New("machine identity is invalid")
	}
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, clientPrivateFilename)
	privateKey, err := loadOrCreateClientKey(path)
	if err != nil {
		return nil, err
	}
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: machineID, Organization: []string{"My Safe"}, OrganizationalUnit: []string{"Agent"}}}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create Agent CSR: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func SaveClientCertificate(stateDir, agentID string, certificatePEM []byte, now time.Time) error {
	if !validIdentifier(agentID, 128) {
		return errors.New("Agent identity is invalid")
	}
	certificate, err := parseCertificatePEM(certificatePEM)
	if err != nil {
		return err
	}
	if !MatchesAgent(certificate, agentID) || now.Before(certificate.NotBefore) || !now.Before(certificate.NotAfter) || !hasClientAuth(certificate) {
		return errors.New("issued Agent certificate has invalid identity, lifetime, or usage")
	}
	keyPEM, err := readRegular(filepath.Join(stateDir, clientPrivateFilename), 1<<20)
	if err != nil {
		return err
	}
	privateKey, err := parseEd25519PrivateKey(keyPEM)
	if err != nil {
		return err
	}
	if !publicKeysEqual(certificate.PublicKey, privateKey.Public()) {
		return errors.New("issued Agent certificate does not match the local private key")
	}
	return writeAtomic(filepath.Join(stateDir, clientCertFilename), certificatePEM, 0o600)
}

func SaveIssuedClientCertificate(stateDir, agentID string, certificatePEM, caPEM []byte, now time.Time) error {
	certificate, err := parseCertificatePEM(certificatePEM)
	if err != nil {
		return err
	}
	caCertificate, err := parseCertificatePEM(caPEM)
	if err != nil || !caCertificate.IsCA {
		return errors.New("issued Agent CA certificate is invalid")
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCertificate)
	if _, err := certificate.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return errors.New("issued Agent certificate does not verify against the returned Agent CA")
	}
	return SaveClientCertificate(stateDir, agentID, certificatePEM, now)
}

func LoadClientCertificate(stateDir string, now time.Time) (tls.Certificate, bool, error) {
	certPath := filepath.Join(stateDir, clientCertFilename)
	keyPath := filepath.Join(stateDir, clientPrivateFilename)
	if !regularFileExists(certPath) {
		return tls.Certificate{}, false, nil
	}
	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, false, fmt.Errorf("load Agent mTLS identity: %w", err)
	}
	if len(certificate.Certificate) == 0 {
		return tls.Certificate{}, false, errors.New("Agent mTLS certificate chain is empty")
	}
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		return tls.Certificate{}, false, err
	}
	if now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) || !hasClientAuth(leaf) {
		return tls.Certificate{}, false, errors.New("Agent mTLS certificate is expired or has invalid usage")
	}
	certificate.Leaf = leaf
	return certificate, true, nil
}

func HTTPClientWithCertificate(base *http.Client, certificate tls.Certificate) (*http.Client, error) {
	if len(certificate.Certificate) == 0 || certificate.PrivateKey == nil {
		return nil, errors.New("complete Agent client certificate is required")
	}
	if base == nil {
		base = &http.Client{Timeout: 15 * time.Second}
	}
	clone := *base
	var transport *http.Transport
	switch configured := base.Transport.(type) {
	case nil:
		transport = http.DefaultTransport.(*http.Transport).Clone()
	case *http.Transport:
		transport = configured.Clone()
	default:
		return nil, errors.New("Agent mTLS requires an HTTP transport that supports TLS configuration")
	}
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS13}
	} else {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
			transport.TLSClientConfig.MinVersion = tls.VersionTLS12
		}
	}
	transport.TLSClientConfig.Certificates = []tls.Certificate{certificate}
	clone.Transport = transport
	return &clone, nil
}

func MatchesAgent(certificate *x509.Certificate, agentID string) bool {
	if certificate == nil || !validIdentifier(agentID, 128) || certificate.Subject.CommonName != agentID || !hasClientAuth(certificate) {
		return false
	}
	want := "spiffe://my-safe/agent/" + agentID
	for _, identity := range certificate.URIs {
		if identity.String() == want {
			return true
		}
	}
	return false
}

func generateCA(certPath, keyPath string, now time.Time) error {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "My Safe Agent CA", Organization: []string{"My Safe"}},
		NotBefore:    now.Add(-5 * time.Minute), NotAfter: now.AddDate(10, 0, 0),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return err
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	if err := writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		return err
	}
	if err := writeNew(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}

func loadOrCreateClientKey(path string) (ed25519.PrivateKey, error) {
	if regularFileExists(path) {
		encoded, err := readRegular(path, 1<<20)
		if err != nil {
			return nil, err
		}
		return parseEd25519PrivateKey(encoded)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	if err := writeNew(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); errors.Is(err, os.ErrExist) {
		return loadOrCreateClientKey(path)
	} else if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func parseCSR(encoded []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("Agent CSR must contain exactly one PEM certificate request")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		return nil, errors.New("Agent CSR is invalid or has a bad signature")
	}
	return request, nil
}

func parseCertificatePEM(encoded []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("certificate file must contain exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("parse certificate")
	}
	return certificate, nil
}

func parseEd25519PrivateKey(encoded []byte) (ed25519.PrivateKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || block.Type != "PRIVATE KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("private key file must contain exactly one PKCS#8 PEM key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("parse private key")
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("private key must be Ed25519")
	}
	return privateKey, nil
}

func hasClientAuth(certificate *x509.Certificate) bool {
	for _, usage := range certificate.ExtKeyUsage {
		if usage == x509.ExtKeyUsageClientAuth {
			return true
		}
	}
	return false
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftDER, rightDER)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	if serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, nil
}

func validIdentifier(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsAny(value, "\x00\r\n/ ")
}

func regularFileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular() && info.Mode()&os.ModeSymlink == 0
}

func readRegular(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > limit {
		return nil, errors.New("file must be a small regular file")
	}
	return os.ReadFile(path)
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("mTLS state directory must be a real directory")
	}
	return os.Chmod(path, 0o700)
}

func writeNew(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		_ = file.Close()
		if !completed {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	completed = true
	return nil
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".mtls-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	completed := false
	defer func() {
		_ = temporary.Close()
		if !completed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(content); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	completed = true
	return nil
}
