package installer

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/id"
)

const transactionDirectory = "/var/lib/my-safe-installer/transactions"

type FileChange struct {
	Path       string `json:"path"`
	BackupPath string `json:"backup_path,omitempty"`
	Existed    bool   `json:"existed"`
	OldMode    uint32 `json:"old_mode,omitempty"`
	NewSHA256  string `json:"new_sha256"`
}

type TransactionRecord struct {
	ID            string          `json:"id"`
	Version       string          `json:"version"`
	CreatedAt     time.Time       `json:"created_at"`
	Status        string          `json:"status"`
	Changes       []FileChange    `json:"changes"`
	CreatedUsers  []string        `json:"created_users,omitempty"`
	CreatedGroups []string        `json:"created_groups,omitempty"`
	Services      []ServiceChange `json:"services,omitempty"`
	NginxChanged  bool            `json:"nginx_changed,omitempty"`
}

type ServiceChange struct {
	Name       string `json:"name"`
	WasEnabled bool   `json:"was_enabled"`
	WasActive  bool   `json:"was_active"`
}

type fileTransaction struct {
	root        string
	record      TransactionRecord
	journalPath string
	backupRoot  string
}

func beginTransaction(root, version string, now time.Time) (*fileTransaction, error) {
	randomID, err := id.Random("", 8)
	if err != nil {
		return nil, fmt.Errorf("generate transaction id: %w", err)
	}
	identifier := fmt.Sprintf("%020d_%s", now.UTC().UnixNano(), randomID)
	journalDirectory := rootPath(root, transactionDirectory)
	if err := os.MkdirAll(journalDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create transaction directory: %w", err)
	}
	transaction := &fileTransaction{
		root: root,
		record: TransactionRecord{
			ID:            identifier,
			Version:       version,
			CreatedAt:     now.UTC(),
			Status:        "applying",
			Changes:       []FileChange{},
			CreatedUsers:  []string{},
			CreatedGroups: []string{},
			Services:      []ServiceChange{},
		},
		journalPath: filepath.Join(journalDirectory, identifier+".json"),
		backupRoot:  rootPath(root, "/var/lib/my-safe-installer/backups/"+identifier),
	}
	if err := os.MkdirAll(transaction.backupRoot, 0o700); err != nil {
		return nil, fmt.Errorf("create transaction backup directory: %w", err)
	}
	if err := transaction.persist(); err != nil {
		return nil, err
	}
	return transaction, nil
}

func (transaction *fileTransaction) RecordCreatedUser(name string) error {
	transaction.record.CreatedUsers = append(transaction.record.CreatedUsers, name)
	return transaction.persist()
}

func (transaction *fileTransaction) RecordCreatedGroup(name string) error {
	transaction.record.CreatedGroups = append(transaction.record.CreatedGroups, name)
	return transaction.persist()
}

func (transaction *fileTransaction) RecordService(change ServiceChange) error {
	transaction.record.Services = append(transaction.record.Services, change)
	return transaction.persist()
}

func (transaction *fileTransaction) RecordNginxChange() error {
	transaction.record.NginxChanged = true
	return transaction.persist()
}

func (transaction *fileTransaction) InstallBytes(unixPath string, content []byte, mode os.FileMode) error {
	if !strings.HasPrefix(unixPath, "/") || filepath.Clean(unixPath) == string(filepath.Separator) {
		return fmt.Errorf("invalid installation path %q", unixPath)
	}
	target := rootPath(transaction.root, unixPath)
	if !withinRoot(transaction.root, target) {
		return fmt.Errorf("installation path escapes root: %q", unixPath)
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return fmt.Errorf("create parent for %s: %w", unixPath, err)
	}
	change := FileChange{Path: unixPath, NewSHA256: hashBytes(content)}
	info, err := os.Lstat(target)
	switch {
	case err == nil:
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("refusing to replace non-regular path %s", unixPath)
		}
		change.Existed = true
		change.OldMode = uint32(info.Mode().Perm())
		change.BackupPath = "/var/lib/my-safe-installer/backups/" + transaction.record.ID + unixPath
		backup := rootPath(transaction.root, change.BackupPath)
		if err := os.MkdirAll(filepath.Dir(backup), 0o700); err != nil {
			return fmt.Errorf("create backup directory: %w", err)
		}
		if err := copyExclusive(target, backup, info.Mode().Perm()); err != nil {
			return fmt.Errorf("back up %s: %w", unixPath, err)
		}
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return fmt.Errorf("inspect %s: %w", unixPath, err)
	}
	transaction.record.Changes = append(transaction.record.Changes, change)
	if err := transaction.persist(); err != nil {
		return err
	}
	if err := writeAtomic(target, content, mode); err != nil {
		return fmt.Errorf("install %s: %w", unixPath, err)
	}
	return nil
}

func (transaction *fileTransaction) Commit() error {
	transaction.record.Status = "complete"
	return transaction.persist()
}

func (transaction *fileTransaction) Rollback() error {
	err := rollbackChanges(transaction.root, transaction.record)
	transaction.record.Status = "rolled_back"
	persistErr := transaction.persist()
	return errors.Join(err, persistErr)
}

func (transaction *fileTransaction) persist() error {
	encoded, err := json.MarshalIndent(transaction.record, "", "  ")
	if err != nil {
		return fmt.Errorf("encode transaction journal: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := writeAtomic(transaction.journalPath, encoded, 0o600); err != nil {
		return fmt.Errorf("persist transaction journal: %w", err)
	}
	return nil
}

func rollbackChanges(root string, record TransactionRecord) error {
	var rollbackErrors []error
	for index := len(record.Changes) - 1; index >= 0; index-- {
		change := record.Changes[index]
		target := rootPath(root, change.Path)
		if !strings.HasPrefix(change.Path, "/") || !withinRoot(root, target) {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("unsafe rollback path %q", change.Path))
			continue
		}
		if change.Existed {
			backup := rootPath(root, change.BackupPath)
			expectedPrefix := "/var/lib/my-safe-installer/backups/" + record.ID + "/"
			if !strings.HasPrefix(change.BackupPath, expectedPrefix) || !withinRoot(root, backup) {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("unsafe backup path %q", change.BackupPath))
				continue
			}
			content, err := os.ReadFile(backup)
			if err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("read backup for %s: %w", change.Path, err))
				continue
			}
			if err := writeAtomic(target, content, os.FileMode(change.OldMode)); err != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("restore %s: %w", change.Path, err))
			}
			continue
		}
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("remove new path %s: %w", change.Path, err))
		}
	}
	return errors.Join(rollbackErrors...)
}

func loadLatestTransaction(root string) (TransactionRecord, string, error) {
	directory := rootPath(root, transactionDirectory)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return TransactionRecord{}, "", fmt.Errorf("read transaction directory: %w", err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	if len(names) == 0 {
		return TransactionRecord{}, "", errors.New("no installation transaction exists")
	}
	sort.Strings(names)
	path := filepath.Join(directory, names[len(names)-1])
	encoded, err := os.ReadFile(path)
	if err != nil {
		return TransactionRecord{}, "", err
	}
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var record TransactionRecord
	if err := decoder.Decode(&record); err != nil {
		return TransactionRecord{}, "", fmt.Errorf("decode transaction journal: %w", err)
	}
	return record, path, nil
}

func writeAtomic(path string, content []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".mysafe-*")
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
	if err := replaceFile(temporaryPath, path); err != nil {
		return err
	}
	completed = true
	return nil
}

func copyExclusive(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		_ = output.Close()
		if !completed {
			_ = os.Remove(destination)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	completed = true
	return nil
}

func hashBytes(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}
