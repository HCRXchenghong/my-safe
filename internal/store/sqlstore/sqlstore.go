package sqlstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	mysqldriver "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/store"
)

type Dialect string

const (
	Postgres Dialect = "postgres"
	MySQL    Dialect = "mysql"
)

type SQLStore struct {
	db      *sql.DB
	dialect Dialect
}

func Open(ctx context.Context, dialect Dialect, dsn string) (*SQLStore, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("database DSN is required")
	}
	var (
		db  *sql.DB
		err error
	)
	switch dialect {
	case Postgres:
		db, err = sql.Open("pgx", dsn)
	case MySQL:
		config, parseErr := mysqldriver.ParseDSN(dsn)
		if parseErr != nil {
			return nil, fmt.Errorf("parse MySQL DSN: %w", parseErr)
		}
		config.ParseTime = true
		config.Loc = time.UTC
		config.MultiStatements = false
		db, err = sql.Open("mysql", config.FormatDSN())
	default:
		return nil, fmt.Errorf("unsupported database dialect %q", dialect)
	}
	if err != nil {
		return nil, fmt.Errorf("open %s database: %w", dialect, err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(10)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping %s database: %w", dialect, err)
	}
	return &SQLStore{db: db, dialect: dialect}, nil
}

func (database *SQLStore) Close() error {
	return database.db.Close()
}

func (database *SQLStore) CreateAgent(ctx context.Context, agent domain.Agent) error {
	query := `INSERT INTO agents
        (id, machine_id, hostname, version, platform, architecture, credential_hash, registered_at, last_seen_at)
        VALUES (` + database.placeholders(1, 9) + `)`
	_, err := database.db.ExecContext(ctx, query,
		agent.ID, agent.MachineID, agent.Hostname, agent.Version, agent.Platform,
		agent.Architecture, agent.CredentialHash, agent.RegisteredAt, agent.LastSeenAt,
	)
	if err != nil {
		if duplicateError(database.dialect, err) {
			return store.ErrConflict
		}
		return fmt.Errorf("insert agent: %w", err)
	}
	return nil
}

func (database *SQLStore) AgentByID(ctx context.Context, id string) (domain.Agent, error) {
	query := `SELECT id, machine_id, hostname, version, platform, architecture, credential_hash, registered_at, last_seen_at
        FROM agents WHERE id = ` + database.placeholder(1)
	return scanAgent(database.db.QueryRowContext(ctx, query, id))
}

func (database *SQLStore) AgentByMachineID(ctx context.Context, machineID string) (domain.Agent, error) {
	query := `SELECT id, machine_id, hostname, version, platform, architecture, credential_hash, registered_at, last_seen_at
        FROM agents WHERE machine_id = ` + database.placeholder(1)
	return scanAgent(database.db.QueryRowContext(ctx, query, machineID))
}

func (database *SQLStore) UpdateHeartbeat(ctx context.Context, id string, heartbeat domain.Heartbeat) error {
	query := `UPDATE agents SET last_seen_at = ` + database.placeholder(1) + `, version = CASE WHEN ` + database.placeholder(2) + ` = '' THEN version ELSE ` + database.placeholder(3) + ` END WHERE id = ` + database.placeholder(4)
	result, err := database.db.ExecContext(ctx, query, heartbeat.SentAt, heartbeat.AgentVersion, heartbeat.AgentVersion, id)
	if err != nil {
		return fmt.Errorf("update heartbeat: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read heartbeat result: %w", err)
	}
	if affected == 0 {
		// MySQL reports changed rows rather than matched rows by default. An
		// identical heartbeat therefore needs an existence check before it can
		// be classified as missing.
		if _, lookupErr := database.AgentByID(ctx, id); lookupErr != nil {
			return lookupErr
		}
	}
	return nil
}

func (database *SQLStore) ListAgents(ctx context.Context, limit int) ([]domain.Agent, error) {
	limit = normalizeLimit(limit)
	query := `SELECT id, machine_id, hostname, version, platform, architecture, registered_at, last_seen_at
        FROM agents ORDER BY registered_at DESC LIMIT ` + database.placeholder(1)
	rows, err := database.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("list agents: %w", err)
	}
	defer rows.Close()
	agents := make([]domain.Agent, 0)
	for rows.Next() {
		var agent domain.Agent
		if err := rows.Scan(&agent.ID, &agent.MachineID, &agent.Hostname, &agent.Version, &agent.Platform, &agent.Architecture, &agent.RegisteredAt, &agent.LastSeenAt); err != nil {
			return nil, fmt.Errorf("scan agent list: %w", err)
		}
		agents = append(agents, agent)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agent list: %w", err)
	}
	return agents, nil
}

func (database *SQLStore) SaveEvents(ctx context.Context, events []domain.Event) (int, error) {
	transaction, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin event transaction: %w", err)
	}
	defer transaction.Rollback()
	inserted := 0
	for _, event := range events {
		evidence, err := json.Marshal(event.Evidence)
		if err != nil {
			return 0, fmt.Errorf("encode event evidence: %w", err)
		}
		query := `INSERT INTO security_events
            (id, agent_id, kind, severity, summary, occurred_at, received_at, evidence)
            VALUES (` + database.placeholders(1, 8) + `)`
		if database.dialect == Postgres {
			query += ` ON CONFLICT (id) DO NOTHING`
		} else {
			query += ` ON DUPLICATE KEY UPDATE id = security_events.id`
		}
		result, err := transaction.ExecContext(ctx, query,
			event.ID, event.AgentID, event.Kind, event.Severity, event.Summary,
			event.OccurredAt, event.ReceivedAt, evidence,
		)
		if err != nil {
			return 0, fmt.Errorf("insert security event: %w", err)
		}
		affected, err := result.RowsAffected()
		if err != nil {
			return 0, fmt.Errorf("read security event result: %w", err)
		}
		if affected == 1 {
			inserted++
		}
	}
	if err := transaction.Commit(); err != nil {
		return 0, fmt.Errorf("commit event transaction: %w", err)
	}
	return inserted, nil
}

func (database *SQLStore) ListAlerts(ctx context.Context, filter domain.AlertFilter) ([]domain.Event, error) {
	limit := normalizeLimit(filter.Limit)
	arguments := make([]any, 0, 2)
	query := `SELECT id, agent_id, kind, severity, summary, occurred_at, received_at, evidence FROM security_events`
	if filter.Severity != "" {
		arguments = append(arguments, filter.Severity)
		query += ` WHERE severity = ` + database.placeholder(len(arguments))
	}
	arguments = append(arguments, limit)
	query += ` ORDER BY received_at DESC LIMIT ` + database.placeholder(len(arguments))
	rows, err := database.db.QueryContext(ctx, query, arguments...)
	if err != nil {
		return nil, fmt.Errorf("list security events: %w", err)
	}
	defer rows.Close()
	alerts := make([]domain.Event, 0)
	for rows.Next() {
		var (
			event    domain.Event
			evidence []byte
		)
		if err := rows.Scan(&event.ID, &event.AgentID, &event.Kind, &event.Severity, &event.Summary, &event.OccurredAt, &event.ReceivedAt, &evidence); err != nil {
			return nil, fmt.Errorf("scan security event: %w", err)
		}
		if err := json.Unmarshal(evidence, &event.Evidence); err != nil {
			return nil, fmt.Errorf("decode event evidence: %w", err)
		}
		alerts = append(alerts, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate security events: %w", err)
	}
	return alerts, nil
}

func (database *SQLStore) PolicyForAgent(ctx context.Context, agentID string) (domain.Policy, error) {
	query := `SELECT id, agent_id, revision, file_integrity_enabled, file_watch_paths,
        ssh_auth_enabled, ssh_threshold, ssh_window_seconds, runtime_watch_enabled, updated_at
        FROM agent_policies WHERE agent_id = ` + database.placeholder(1)
	var policy domain.Policy
	var paths []byte
	err := database.db.QueryRowContext(ctx, query, agentID).Scan(
		&policy.ID, &policy.AgentID, &policy.Revision, &policy.FileIntegrityEnabled, &paths,
		&policy.SSHAuthEnabled, &policy.SSHThreshold, &policy.SSHWindowSeconds,
		&policy.RuntimeWatchEnabled, &policy.UpdatedAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Policy{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Policy{}, fmt.Errorf("read Agent policy: %w", err)
	}
	if err := json.Unmarshal(paths, &policy.FileWatchPaths); err != nil {
		return domain.Policy{}, fmt.Errorf("decode policy file paths: %w", err)
	}
	return policy, nil
}

func (database *SQLStore) SavePolicyAndAudit(ctx context.Context, policy domain.Policy, expectedRevision int64, audit domain.AuditLog) error {
	if expectedRevision < 0 || policy.Revision != expectedRevision+1 {
		return store.ErrConflict
	}
	paths, err := json.Marshal(policy.FileWatchPaths)
	if err != nil {
		return fmt.Errorf("encode policy paths: %w", err)
	}
	details, err := json.Marshal(audit.Details)
	if err != nil {
		return fmt.Errorf("encode audit details: %w", err)
	}
	transaction, err := database.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin policy transaction: %w", err)
	}
	defer transaction.Rollback()
	var currentRevision int64
	lockQuery := `SELECT revision FROM agent_policies WHERE agent_id = ` + database.placeholder(1) + ` FOR UPDATE`
	err = transaction.QueryRowContext(ctx, lockQuery, policy.AgentID).Scan(&currentRevision)
	switch {
	case errors.Is(err, sql.ErrNoRows) && expectedRevision == 0:
		query := `INSERT INTO agent_policies
            (id, agent_id, revision, file_integrity_enabled, file_watch_paths, ssh_auth_enabled,
             ssh_threshold, ssh_window_seconds, runtime_watch_enabled, updated_at)
            VALUES (` + database.placeholders(1, 10) + `)`
		if _, err := transaction.ExecContext(ctx, query, policy.ID, policy.AgentID, policy.Revision,
			policy.FileIntegrityEnabled, paths, policy.SSHAuthEnabled, policy.SSHThreshold,
			policy.SSHWindowSeconds, policy.RuntimeWatchEnabled, policy.UpdatedAt); err != nil {
			if duplicateError(database.dialect, err) {
				return store.ErrConflict
			}
			return fmt.Errorf("insert Agent policy: %w", err)
		}
	case err == nil && currentRevision == expectedRevision:
		query := `UPDATE agent_policies SET revision = ` + database.placeholder(1) +
			`, file_integrity_enabled = ` + database.placeholder(2) +
			`, file_watch_paths = ` + database.placeholder(3) +
			`, ssh_auth_enabled = ` + database.placeholder(4) +
			`, ssh_threshold = ` + database.placeholder(5) +
			`, ssh_window_seconds = ` + database.placeholder(6) +
			`, runtime_watch_enabled = ` + database.placeholder(7) +
			`, updated_at = ` + database.placeholder(8) +
			` WHERE agent_id = ` + database.placeholder(9) + ` AND revision = ` + database.placeholder(10)
		result, updateErr := transaction.ExecContext(ctx, query, policy.Revision, policy.FileIntegrityEnabled, paths,
			policy.SSHAuthEnabled, policy.SSHThreshold, policy.SSHWindowSeconds,
			policy.RuntimeWatchEnabled, policy.UpdatedAt, policy.AgentID, expectedRevision)
		if updateErr != nil {
			return fmt.Errorf("update Agent policy: %w", updateErr)
		}
		affected, rowsErr := result.RowsAffected()
		if rowsErr != nil || affected != 1 {
			return store.ErrConflict
		}
	case err == nil || errors.Is(err, sql.ErrNoRows):
		return store.ErrConflict
	default:
		return fmt.Errorf("lock Agent policy: %w", err)
	}
	auditQuery := `INSERT INTO audit_logs (id, actor, action, resource, occurred_at, details) VALUES (` + database.placeholders(1, 6) + `)`
	if _, err := transaction.ExecContext(ctx, auditQuery, audit.ID, audit.Actor, audit.Action, audit.Resource, audit.OccurredAt, details); err != nil {
		return fmt.Errorf("insert policy audit log: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit policy transaction: %w", err)
	}
	return nil
}

func (database *SQLStore) ListAuditLogs(ctx context.Context, limit int) ([]domain.AuditLog, error) {
	limit = normalizeLimit(limit)
	query := `SELECT id, actor, action, resource, occurred_at, details FROM audit_logs ORDER BY occurred_at DESC LIMIT ` + database.placeholder(1)
	rows, err := database.db.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()
	logs := make([]domain.AuditLog, 0)
	for rows.Next() {
		var audit domain.AuditLog
		var details []byte
		if err := rows.Scan(&audit.ID, &audit.Actor, &audit.Action, &audit.Resource, &audit.OccurredAt, &details); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		if err := json.Unmarshal(details, &audit.Details); err != nil {
			return nil, fmt.Errorf("decode audit log details: %w", err)
		}
		logs = append(logs, audit)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate audit logs: %w", err)
	}
	return logs, nil
}

type rowScanner interface {
	Scan(...any) error
}

func scanAgent(row rowScanner) (domain.Agent, error) {
	var agent domain.Agent
	err := row.Scan(
		&agent.ID, &agent.MachineID, &agent.Hostname, &agent.Version,
		&agent.Platform, &agent.Architecture, &agent.CredentialHash,
		&agent.RegisteredAt, &agent.LastSeenAt,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Agent{}, store.ErrNotFound
	}
	if err != nil {
		return domain.Agent{}, fmt.Errorf("scan agent: %w", err)
	}
	return agent, nil
}

func (database *SQLStore) placeholder(index int) string {
	if database.dialect == Postgres {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func (database *SQLStore) placeholders(start, count int) string {
	values := make([]string, count)
	for index := range values {
		values[index] = database.placeholder(start + index)
	}
	return strings.Join(values, ", ")
}

func normalizeLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 500 {
		return 500
	}
	return limit
}

func duplicateError(dialect Dialect, err error) bool {
	if dialect == MySQL {
		var mysqlError *mysqldriver.MySQLError
		return errors.As(err, &mysqlError) && mysqlError.Number == 1062
	}
	// PostgreSQL errors expose SQLSTATE through this interface without coupling
	// the repository contract to a concrete pgx error type.
	type sqlState interface{ SQLState() string }
	var state sqlState
	return errors.As(err, &state) && state.SQLState() == "23505"
}

var _ store.Store = (*SQLStore)(nil)
