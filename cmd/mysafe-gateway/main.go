package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/gateway"
	"github.com/HCRXchenghong/my-safe/internal/gatewayevents"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mysafe-gateway:", err)
		os.Exit(1)
	}
}

func run() error {
	address := flag.String("address", envOr("MYSAFE_GATEWAY_ADDRESS", ":8081"), "HTTP listen address")
	upstream := flag.String("upstream", os.Getenv("MYSAFE_GATEWAY_UPSTREAM"), "protected upstream HTTP(S) URL")
	mode := flag.String("mode", envOr("MYSAFE_GATEWAY_MODE", "observe"), "gateway mode: bypass, observe, or block")
	failurePolicy := flag.String("failure-policy", envOr("MYSAFE_GATEWAY_FAILURE_POLICY", "fail_open"), "WAF failure policy: fail_open or fail_closed")
	bodyLimit := flag.Int("request-body-limit", 1<<20, "maximum inspected request body bytes")
	memoryLimit := flag.Int("request-memory-limit", 256<<10, "maximum request bytes buffered in memory")
	tlsCertificate := flag.String("tls-cert", os.Getenv("MYSAFE_GATEWAY_TLS_CERT"), "TLS certificate path")
	tlsKey := flag.String("tls-key", os.Getenv("MYSAFE_GATEWAY_TLS_KEY"), "TLS private key path")
	eventSocket := flag.String("event-socket", envOr("MYSAFE_GATEWAY_EVENT_SOCKET", defaultEventSocket()), "Agent Unix datagram event socket; empty disables local event forwarding")
	eventStateDir := flag.String("event-state-dir", envOr("MYSAFE_GATEWAY_STATE_DIR", defaultEventStateDir()), "Gateway event outbox state directory")
	flag.Parse()
	if strings.TrimSpace(*upstream) == "" {
		return errors.New("-upstream is required")
	}
	if (*tlsCertificate == "") != (*tlsKey == "") {
		return errors.New("-tls-cert and -tls-key must be configured together")
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	var eventOutbox *gatewayevents.Outbox
	if strings.TrimSpace(*eventSocket) != "" {
		outbox, outboxErr := gatewayevents.New(gatewayevents.Config{StateDir: *eventStateDir, SocketPath: *eventSocket})
		if outboxErr != nil {
			return outboxErr
		}
		eventOutbox = outbox
	}
	handler, err := gateway.New(gateway.Config{
		Mode:                    gateway.Mode(strings.ToLower(strings.TrimSpace(*mode))),
		FailurePolicy:           gateway.FailurePolicy(strings.ToLower(strings.TrimSpace(*failurePolicy))),
		Upstream:                *upstream,
		RequestBodyLimitBytes:   *bodyLimit,
		RequestMemoryLimitBytes: *memoryLimit,
		Logger:                  logger,
		EventSink:               eventOutbox,
	})
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              *address,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if eventOutbox != nil {
		go func() {
			if err := eventOutbox.Run(ctx, 2*time.Second); err != nil {
				logger.Error("Gateway event outbox stopped", "error", err)
			}
		}()
	}
	serverError := make(chan error, 1)
	go func() {
		logger.Info("gateway listening", "address", *address, "mode", *mode)
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
		shutdownContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	}
}

func defaultEventSocket() string {
	if runtime.GOOS == "linux" {
		return "/run/my-safe/gateway-events.sock"
	}
	return ""
}

func defaultEventStateDir() string {
	if runtime.GOOS == "linux" {
		return "/var/lib/my-safe-gateway"
	}
	return ".local/gateway"
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}
