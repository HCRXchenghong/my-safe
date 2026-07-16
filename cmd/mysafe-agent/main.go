package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/agent"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "mysafe-agent:", err)
		os.Exit(1)
	}
}

func run() error {
	controlURL := flag.String("control-url", os.Getenv("MYSAFE_CONTROL_URL"), "control-plane base URL")
	bootstrapToken := flag.String("bootstrap-token", os.Getenv("MYSAFE_BOOTSTRAP_TOKEN"), "short-lived registration token")
	stateDir := flag.String("state-dir", envOr("MYSAFE_STATE_DIR", "/var/lib/my-safe"), "private agent state directory")
	interval := flag.Duration("interval", time.Minute, "scan and delivery interval")
	once := flag.Bool("once", false, "run one scan and delivery cycle")
	allowInsecureHTTP := flag.Bool("allow-insecure-http", false, "allow plain HTTP to non-loopback control endpoints")
	fileWatchPaths := flag.String("file-watch-paths", os.Getenv("MYSAFE_FILE_WATCH_PATHS"), "comma-separated file integrity roots; empty uses Linux defaults")
	disableFileIntegrity := flag.Bool("disable-file-integrity", false, "disable the file integrity detector")
	sshAuthLogPaths := flag.String("ssh-auth-log-paths", os.Getenv("MYSAFE_SSH_AUTH_LOG_PATHS"), "comma-separated SSH authentication log files; empty uses Linux defaults")
	disableSSHAuth := flag.Bool("disable-ssh-auth", false, "disable the SSH authentication detector")
	disableRuntimeWatch := flag.Bool("disable-runtime-watch", false, "disable the process and listening-port detector")
	gatewayEventSocket := flag.String("gateway-event-socket", os.Getenv("MYSAFE_GATEWAY_EVENT_SOCKET"), "Gateway Unix datagram event socket; empty uses the Linux default")
	disableGatewayFeed := flag.Bool("disable-gateway-feed", false, "disable the local Gateway event receiver")
	flag.Parse()

	if *controlURL == "" {
		return fmt.Errorf("-control-url is required")
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	config := agent.Config{
		StateDir:             *stateDir,
		ControlURL:           *controlURL,
		BootstrapToken:       *bootstrapToken,
		AllowInsecureHTTP:    *allowInsecureHTTP,
		Interval:             *interval,
		Logger:               logger,
		DisableFileIntegrity: *disableFileIntegrity,
		FileWatchPaths:       splitPaths(*fileWatchPaths),
		DisableSSHAuth:       *disableSSHAuth,
		SSHAuthLogPaths:      splitPaths(*sshAuthLogPaths),
		DisableRuntimeWatch:  *disableRuntimeWatch,
		GatewayEventSocket:   *gatewayEventSocket,
		DisableGatewayFeed:   *disableGatewayFeed,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if *once {
		return agent.RunOnce(ctx, config)
	}
	return agent.Run(ctx, config)
}

func splitPaths(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		if path := strings.TrimSpace(part); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
