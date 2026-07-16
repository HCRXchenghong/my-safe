package sqlstore

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/store"
)

func TestPlaceholderDialects(t *testing.T) {
	t.Parallel()
	postgres := &SQLStore{dialect: Postgres}
	if got := postgres.placeholders(1, 3); got != "$1, $2, $3" {
		t.Fatalf("Postgres placeholders = %q", got)
	}
	mysql := &SQLStore{dialect: MySQL}
	if got := mysql.placeholders(1, 3); got != "?, ?, ?" {
		t.Fatalf("MySQL placeholders = %q", got)
	}
}

func TestSplitStatements(t *testing.T) {
	t.Parallel()
	got := splitStatements(" CREATE TABLE one (id INT);\n" + statementDelimiter + "\nCREATE TABLE two (id INT); ")
	if len(got) != 2 {
		t.Fatalf("splitStatements() = %#v", got)
	}
}

func TestPostgresContract(t *testing.T) {
	runDatabaseContract(t, Postgres, "MYSAFE_TEST_POSTGRES_DSN")
}

func TestMySQLContract(t *testing.T) {
	runDatabaseContract(t, MySQL, "MYSAFE_TEST_MYSQL_DSN")
}

func runDatabaseContract(t *testing.T, dialect Dialect, environmentName string) {
	t.Helper()
	dsn := os.Getenv(environmentName)
	if dsn == "" {
		t.Skipf("%s is not configured", environmentName)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := Open(ctx, dialect, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	suffix := now.Format("20060102150405.000000000")
	agent := domain.Agent{
		ID:             "contract-agent-" + suffix,
		MachineID:      "contract-machine-" + suffix,
		Hostname:       "contract-host",
		Version:        "test",
		Platform:       "linux",
		Architecture:   "amd64",
		CredentialHash: make([]byte, 32),
		RegisteredAt:   now,
		LastSeenAt:     now,
	}
	if err := database.CreateAgent(ctx, agent); err != nil {
		t.Fatal(err)
	}
	stored, err := database.AgentByID(ctx, agent.ID)
	if err != nil || stored.MachineID != agent.MachineID {
		t.Fatalf("AgentByID() = %#v, %v", stored, err)
	}
	event := domain.Event{
		ID:         "contract-event-" + suffix,
		AgentID:    agent.ID,
		Kind:       "contract.test",
		Severity:   domain.SeverityInfo,
		Summary:    "database contract test",
		OccurredAt: now,
		ReceivedAt: now,
		Evidence:   map[string]any{"dialect": string(dialect)},
	}
	inserted, err := database.SaveEvents(ctx, []domain.Event{event, event})
	if err != nil || inserted != 1 {
		t.Fatalf("SaveEvents() = %d, %v", inserted, err)
	}
	alerts, err := database.ListAlerts(ctx, domain.AlertFilter{Limit: 10})
	if err != nil || len(alerts) == 0 {
		t.Fatalf("ListAlerts() = %#v, %v", alerts, err)
	}
	policy := domain.Policy{
		ID: "contract-policy-" + suffix, AgentID: agent.ID, Revision: 1,
		FileIntegrityEnabled: true, FileWatchPaths: []string{"/etc/nginx"},
		SSHAuthEnabled: true, SSHThreshold: 5, SSHWindowSeconds: 300,
		RuntimeWatchEnabled: true, UpdatedAt: now,
	}
	audit := domain.AuditLog{
		ID: "contract-audit-" + suffix, Actor: "contract", Action: "agent.policy.updated",
		Resource: "agent/" + agent.ID + "/policy", OccurredAt: now,
		Details: map[string]any{"revision": 1},
	}
	if err := database.SavePolicyAndAudit(ctx, policy, 0, audit); err != nil {
		t.Fatal(err)
	}
	if err := database.SavePolicyAndAudit(ctx, policy, 0, audit); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("stale SavePolicyAndAudit() = %v", err)
	}
	storedPolicy, err := database.PolicyForAgent(ctx, agent.ID)
	if err != nil || storedPolicy.ID != policy.ID || len(storedPolicy.FileWatchPaths) != 1 {
		t.Fatalf("PolicyForAgent() = %#v, %v", storedPolicy, err)
	}
	audits, err := database.ListAuditLogs(ctx, 10)
	if err != nil || len(audits) == 0 {
		t.Fatalf("ListAuditLogs() = %#v, %v", audits, err)
	}
}
