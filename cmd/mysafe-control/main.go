package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/control"
	"github.com/HCRXchenghong/my-safe/internal/mtls"
	"github.com/HCRXchenghong/my-safe/internal/store"
	"github.com/HCRXchenghong/my-safe/internal/store/sqlstore"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mysafe-control:", err)
		os.Exit(1)
	}
}

func run() error {
	address := flag.String("address", envOr("MYSAFE_ADDRESS", ":8080"), "HTTP listen address")
	storeMode := flag.String("store", os.Getenv("MYSAFE_STORE"), "storage mode: memory, postgres, or mysql")
	databaseDSN := flag.String("database-dsn", os.Getenv("MYSAFE_DATABASE_DSN"), "database connection string; never logged")
	migrate := flag.Bool("migrate", true, "apply embedded database migrations before serving")
	bootstrapToken := flag.String("bootstrap-token", os.Getenv("MYSAFE_BOOTSTRAP_TOKEN"), "short-lived agent registration token")
	adminToken := flag.String("admin-token", os.Getenv("MYSAFE_ADMIN_TOKEN"), "control-plane administration token")
	tlsCertificate := flag.String("tls-cert", os.Getenv("MYSAFE_TLS_CERT"), "control-plane TLS certificate path")
	tlsKey := flag.String("tls-key", os.Getenv("MYSAFE_TLS_KEY"), "control-plane TLS private key path")
	agentCADir := flag.String("agent-ca-dir", os.Getenv("MYSAFE_AGENT_CA_DIR"), "private directory containing the generated Agent client CA")
	requireAgentMTLS := flag.Bool("require-agent-mtls", envBool("MYSAFE_REQUIRE_AGENT_MTLS"), "require a valid Agent client certificate in addition to its device token")
	flag.Parse()

	if len(*bootstrapToken) < 16 || len(*adminToken) < 16 {
		return errors.New("bootstrap and admin tokens must each contain at least 16 bytes")
	}
	if (*tlsCertificate == "") != (*tlsKey == "") {
		return errors.New("-tls-cert and -tls-key must be configured together")
	}
	if *agentCADir != "" && *tlsCertificate == "" {
		return errors.New("Agent certificate issuance requires HTTPS with -tls-cert and -tls-key")
	}
	if *requireAgentMTLS && (*agentCADir == "" || *tlsCertificate == "") {
		return errors.New("required Agent mTLS needs HTTPS and -agent-ca-dir")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	mode := strings.ToLower(strings.TrimSpace(*storeMode))
	var backingStore store.Store
	var closeStore func() error
	switch mode {
	case "memory":
		backingStore = store.NewMemory()
	case string(sqlstore.Postgres), string(sqlstore.MySQL):
		connectContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		database, err := sqlstore.Open(connectContext, sqlstore.Dialect(mode), *databaseDSN)
		cancel()
		if err != nil {
			return err
		}
		closeStore = database.Close
		if *migrate {
			migrationContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err = database.Migrate(migrationContext)
			cancel()
			if err != nil {
				_ = database.Close()
				return err
			}
		}
		backingStore = database
	default:
		return errors.New("-store must be explicitly set to memory, postgres, or mysql")
	}
	if closeStore != nil {
		defer closeStore()
	}
	var agentIssuer *mtls.Issuer
	if *agentCADir != "" {
		issuer, issuerErr := mtls.LoadOrCreateIssuer(*agentCADir, time.Now().UTC())
		if issuerErr != nil {
			return issuerErr
		}
		agentIssuer = issuer
	}
	handler, err := control.New(control.Config{
		Store:            backingStore,
		BootstrapToken:   *bootstrapToken,
		AdminToken:       *adminToken,
		Logger:           logger,
		AgentIssuer:      agentIssuer,
		RequireAgentMTLS: *requireAgentMTLS,
	})
	if err != nil {
		return err
	}

	server := &http.Server{
		Addr:              *address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	if agentIssuer != nil {
		server.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
			ClientAuth: tls.VerifyClientCertIfGiven,
			ClientCAs:  agentIssuer.CertPool(),
		}
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	serverError := make(chan error, 1)
	go func() {
		logger.Info("control plane listening", "address", *address, "store", mode, "tls", *tlsCertificate != "", "agent_mtls_required", *requireAgentMTLS)
		if *tlsCertificate != "" {
			serverError <- server.ListenAndServeTLS(*tlsCertificate, *tlsKey)
			return
		}
		serverError <- server.ListenAndServe()
	}()

	select {
	case err := <-serverError:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	}
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func envBool(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
