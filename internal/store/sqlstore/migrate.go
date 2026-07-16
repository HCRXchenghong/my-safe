package sqlstore

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

//go:embed migrations/postgres/*.sql migrations/mysql/*.sql
var migrationFiles embed.FS

const statementDelimiter = "-- mysafe:statement"

func (database *SQLStore) Migrate(ctx context.Context) error {
	if _, err := database.db.ExecContext(ctx, database.migrationTableDDL()); err != nil {
		return fmt.Errorf("create schema migration table: %w", err)
	}
	directory := "migrations/" + string(database.dialect)
	paths, err := fs.Glob(migrationFiles, directory+"/*.sql")
	if err != nil {
		return fmt.Errorf("list migrations: %w", err)
	}
	sort.Strings(paths)
	for _, path := range paths {
		version := strings.TrimPrefix(path, directory+"/")
		applied, err := database.migrationApplied(ctx, version)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		content, err := migrationFiles.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", version, err)
		}
		for _, statement := range splitStatements(string(content)) {
			if _, err := database.db.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply migration %s: %w", version, err)
			}
		}
		query := `INSERT INTO schema_migrations (version) VALUES (` + database.placeholder(1) + `)`
		if database.dialect == Postgres {
			query += ` ON CONFLICT (version) DO NOTHING`
		} else {
			query += ` ON DUPLICATE KEY UPDATE version = schema_migrations.version`
		}
		if _, err := database.db.ExecContext(ctx, query, version); err != nil {
			return fmt.Errorf("record migration %s: %w", version, err)
		}
	}
	return nil
}

func (database *SQLStore) migrationApplied(ctx context.Context, version string) (bool, error) {
	query := `SELECT COUNT(*) FROM schema_migrations WHERE version = ` + database.placeholder(1)
	var count int
	if err := database.db.QueryRowContext(ctx, query, version).Scan(&count); err != nil {
		return false, fmt.Errorf("check migration %s: %w", version, err)
	}
	return count > 0, nil
}

func (database *SQLStore) migrationTableDDL() string {
	if database.dialect == Postgres {
		return `CREATE TABLE IF NOT EXISTS schema_migrations (
            version VARCHAR(255) PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
        )`
	}
	return `CREATE TABLE IF NOT EXISTS schema_migrations (
        version VARCHAR(255) PRIMARY KEY,
        applied_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
    ) ENGINE=InnoDB`
}

func splitStatements(content string) []string {
	parts := strings.Split(content, statementDelimiter)
	statements := make([]string, 0, len(parts))
	for _, part := range parts {
		statement := strings.TrimSpace(part)
		if statement != "" {
			statements = append(statements, statement)
		}
	}
	return statements
}
