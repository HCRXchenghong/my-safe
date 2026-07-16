package fileintegrity

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

const (
	baselineSchemaVersion = 1
	baselineFilename      = "file-integrity-baseline.json"
	defaultMaxFiles       = 10_000
	defaultMaxFileBytes   = int64(64 << 20)
	defaultMaxEvents      = 500
	maxBaselineBytes      = int64(16 << 20)
	maxIssueSamples       = 20
)

var errFileLimit = errors.New("file integrity path exceeds scan limit")

type Config struct {
	StateDir    string
	Paths       []string
	Now         func() time.Time
	MaxFiles    int
	MaxFileSize int64
	MaxEvents   int
}

type Detector struct {
	config Config
}

// Result separates observation from baseline persistence. The Agent queues
// every event before calling Commit, so a crash cannot silently advance the
// baseline past a change that was never persisted.
type Result struct {
	Events []domain.Event
	Commit func() error
}

type entry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

type baseline struct {
	SchemaVersion int              `json:"schema_version"`
	Generation    uint64           `json:"generation"`
	CoverageHash  string           `json:"coverage_hash,omitempty"`
	Entries       map[string]entry `json:"entries"`
}

type scanIssue struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type snapshot struct {
	entries map[string]entry
	issues  []scanIssue
	limited bool
}

func New(config Config) (*Detector, error) {
	if strings.TrimSpace(config.StateDir) == "" {
		return nil, errors.New("file integrity state directory is required")
	}
	stateDir, err := filepath.Abs(config.StateDir)
	if err != nil {
		return nil, fmt.Errorf("resolve file integrity state directory: %w", err)
	}
	config.StateDir = stateDir
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxFiles == 0 {
		config.MaxFiles = defaultMaxFiles
	}
	if config.MaxFiles < 1 || config.MaxFiles > 100_000 {
		return nil, errors.New("file integrity max files must be between 1 and 100000")
	}
	if config.MaxFileSize == 0 {
		config.MaxFileSize = defaultMaxFileBytes
	}
	if config.MaxFileSize < 1 || config.MaxFileSize > 1<<30 {
		return nil, errors.New("file integrity max file size must be between 1 byte and 1 GiB")
	}
	if config.MaxEvents == 0 {
		config.MaxEvents = defaultMaxEvents
	}
	if config.MaxEvents < 1 || config.MaxEvents > 5000 {
		return nil, errors.New("file integrity max events must be between 1 and 5000")
	}

	paths := make([]string, 0, len(config.Paths))
	seen := make(map[string]bool, len(config.Paths))
	for _, raw := range config.Paths {
		if strings.ContainsAny(raw, "\x00\r\n") {
			return nil, errors.New("file integrity path contains control characters")
		}
		path, err := filepath.Abs(strings.TrimSpace(raw))
		if err != nil || strings.TrimSpace(raw) == "" {
			return nil, fmt.Errorf("invalid file integrity path %q", raw)
		}
		path = filepath.Clean(path)
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	config.Paths = paths
	return &Detector{config: config}, nil
}

func DefaultPaths() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	return []string{
		"/etc/cron.d",
		"/etc/nginx",
		"/etc/ssh/sshd_config",
		"/etc/sudoers",
		"/etc/sudoers.d",
		"/etc/systemd/system",
		"/var/spool/cron",
	}
}

func (detector *Detector) Scan(ctx context.Context) (Result, error) {
	current, err := detector.capture(ctx)
	if err != nil {
		return Result{}, err
	}
	previous, exists, err := detector.loadBaseline()
	if err != nil {
		return Result{}, err
	}
	now := detector.config.Now().UTC()
	coverageHash := hashIssues(current.issues, current.limited)

	if current.limited {
		event := coverageEvent(now, previous.Generation, current.issues, true, "File integrity scan exceeded its configured file limit", domain.SeverityHigh)
		return Result{Events: []domain.Event{event}, Commit: func() error { return nil }}, nil
	}

	if exists {
		preserveInaccessible(previous.Entries, current.entries, current.issues)
	}
	nextGeneration := uint64(1)
	if exists {
		if previous.Generation == ^uint64(0) {
			return Result{}, errors.New("file integrity baseline generation is exhausted")
		}
		nextGeneration = previous.Generation + 1
	}
	next := baseline{SchemaVersion: baselineSchemaVersion, Generation: nextGeneration, CoverageHash: coverageHash, Entries: current.entries}
	events := make([]domain.Event, 0)
	if exists {
		events = detector.changeEvents(previous.Entries, current.entries, now, previous.Generation)
	}
	if coverageHash != previous.CoverageHash {
		switch {
		case len(current.issues) > 0:
			events = append(events, coverageEvent(now, previous.Generation, current.issues, false, "File integrity coverage is limited", domain.SeverityMedium))
		case exists && previous.CoverageHash != "":
			events = append(events, simpleEvent("file.integrity.coverage_restored", domain.SeverityInfo, "File integrity coverage was restored", now, previous.Generation, map[string]any{"read_only": true}))
		}
	}

	return Result{
		Events: events,
		Commit: func() error {
			return detector.saveBaseline(next)
		},
	}, nil
}

func (detector *Detector) capture(ctx context.Context) (snapshot, error) {
	result := snapshot{entries: make(map[string]entry)}
	for _, root := range detector.config.Paths {
		if err := ctx.Err(); err != nil {
			return snapshot{}, err
		}
		info, err := os.Lstat(root)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			result.issues = append(result.issues, scanIssue{Path: root, Reason: "unreadable"})
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			result.issues = append(result.issues, scanIssue{Path: root, Reason: "symlink_skipped"})
			continue
		}
		if info.Mode().IsRegular() {
			if err := detector.captureFile(root, info, &result); errors.Is(err, errFileLimit) {
				result.limited = true
				break
			}
			continue
		}
		if !info.IsDir() {
			result.issues = append(result.issues, scanIssue{Path: root, Reason: "unsupported_file_type"})
			continue
		}
		err = filepath.WalkDir(root, func(path string, item os.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				result.issues = append(result.issues, scanIssue{Path: path, Reason: "unreadable"})
				if item != nil && item.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if item.Type()&os.ModeSymlink != 0 {
				if item.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !item.Type().IsRegular() {
				return nil
			}
			info, err := item.Info()
			if err != nil {
				result.issues = append(result.issues, scanIssue{Path: path, Reason: "unreadable"})
				return nil
			}
			return detector.captureFile(path, info, &result)
		})
		if errors.Is(err, errFileLimit) {
			result.limited = true
			break
		}
		if err != nil {
			return snapshot{}, err
		}
	}
	sort.Slice(result.issues, func(i, j int) bool {
		if result.issues[i].Path == result.issues[j].Path {
			return result.issues[i].Reason < result.issues[j].Reason
		}
		return result.issues[i].Path < result.issues[j].Path
	})
	return result, nil
}

func (detector *Detector) captureFile(path string, info os.FileInfo, result *snapshot) error {
	if len(result.entries) >= detector.config.MaxFiles {
		result.issues = append(result.issues, scanIssue{Path: path, Reason: "file_limit_exceeded"})
		return errFileLimit
	}
	value := entry{Path: filepath.Clean(path), Size: info.Size(), Mode: uint32(info.Mode().Perm())}
	if info.Size() > detector.config.MaxFileSize {
		result.entries[value.Path] = value
		result.issues = append(result.issues, scanIssue{Path: value.Path, Reason: "file_too_large_to_hash"})
		return nil
	}
	digest, err := hashFile(path, detector.config.MaxFileSize)
	if err != nil {
		result.issues = append(result.issues, scanIssue{Path: value.Path, Reason: "unreadable"})
		return nil
	}
	value.SHA256 = digest
	result.entries[value.Path] = value
	return nil
}

func (detector *Detector) changeEvents(previous, current map[string]entry, now time.Time, generation uint64) []domain.Event {
	paths := make([]string, 0, len(previous)+len(current))
	seen := make(map[string]bool, len(previous)+len(current))
	for path := range previous {
		seen[path] = true
		paths = append(paths, path)
	}
	for path := range current {
		if !seen[path] {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	totalChanges := 0
	events := make([]domain.Event, 0)
	for _, path := range paths {
		before, hadBefore := previous[path]
		after, hasAfter := current[path]
		change := ""
		severity := domain.SeverityHigh
		switch {
		case !hadBefore && hasAfter:
			change = "created"
			severity = domain.SeverityMedium
		case hadBefore && !hasAfter:
			change = "deleted"
		case before.SHA256 != after.SHA256 || before.Size != after.Size:
			if before.Mode != after.Mode {
				change = "content_and_mode_changed"
			} else {
				change = "content_changed"
			}
		case before.Mode != after.Mode:
			change = "mode_changed"
		}
		if change == "" {
			continue
		}
		totalChanges++
		if len(events) >= detector.config.MaxEvents {
			continue
		}
		evidence := map[string]any{"path": path, "change": change, "read_only": true}
		if hadBefore {
			evidence["previous"] = before
		}
		if hasAfter {
			evidence["current"] = after
		}
		events = append(events, simpleEvent(
			"file.integrity.changed",
			severity,
			"Protected file "+strings.ReplaceAll(change, "_", " "),
			now,
			generation,
			evidence,
		))
	}
	if totalChanges > detector.config.MaxEvents {
		events = append(events, simpleEvent(
			"file.integrity.change_overflow",
			domain.SeverityCritical,
			"File integrity changes exceeded the per-cycle event limit",
			now,
			generation,
			map[string]any{"total_changes": totalChanges, "reported_changes": detector.config.MaxEvents, "read_only": true},
		))
	}
	return events
}

func (detector *Detector) loadBaseline() (baseline, bool, error) {
	path := filepath.Join(detector.config.StateDir, "detectors", baselineFilename)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return baseline{Entries: make(map[string]entry)}, false, nil
	}
	if err != nil {
		return baseline{}, false, fmt.Errorf("stat file integrity baseline: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxBaselineBytes {
		return baseline{}, false, errors.New("file integrity baseline must be a small regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return baseline{}, false, fmt.Errorf("open file integrity baseline: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(file, maxBaselineBytes+1)))
	decoder.DisallowUnknownFields()
	var value baseline
	if err := decoder.Decode(&value); err != nil {
		return baseline{}, false, fmt.Errorf("decode file integrity baseline: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return baseline{}, false, errors.New("file integrity baseline contains trailing JSON")
	}
	if err := validateBaseline(value, detector.config.MaxFiles); err != nil {
		return baseline{}, false, err
	}
	return value, true, nil
}

func (detector *Detector) saveBaseline(value baseline) error {
	if err := validateBaseline(value, detector.config.MaxFiles); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode file integrity baseline: %w", err)
	}
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > maxBaselineBytes {
		return errors.New("file integrity baseline exceeds size limit")
	}
	directory := filepath.Join(detector.config.StateDir, "detectors")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create detector state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect detector state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".file-integrity-*.tmp")
	if err != nil {
		return fmt.Errorf("create file integrity baseline: %w", err)
	}
	temporaryPath := temporary.Name()
	completed := false
	defer func() {
		_ = temporary.Close()
		if !completed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	path := filepath.Join(directory, baselineFilename)
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("replace file integrity baseline: %w", err)
	}
	completed = true
	return nil
}

func validateBaseline(value baseline, maxFiles int) error {
	if value.SchemaVersion != baselineSchemaVersion {
		return fmt.Errorf("unsupported file integrity baseline schema %d", value.SchemaVersion)
	}
	if value.Generation == 0 {
		return errors.New("file integrity baseline generation is required")
	}
	if value.Entries == nil || len(value.Entries) > maxFiles {
		return errors.New("file integrity baseline has an invalid entry count")
	}
	for path, item := range value.Entries {
		if path != item.Path || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return errors.New("file integrity baseline contains an invalid path")
		}
		if item.Size < 0 || item.Mode&^uint32(0o777) != 0 {
			return errors.New("file integrity baseline contains invalid metadata")
		}
		if item.SHA256 != "" {
			digest, err := hex.DecodeString(item.SHA256)
			if err != nil || len(digest) != sha256.Size || item.SHA256 != strings.ToLower(item.SHA256) {
				return errors.New("file integrity baseline contains an invalid hash")
			}
		}
	}
	return nil
}

func preserveInaccessible(previous, current map[string]entry, issues []scanIssue) {
	for _, issue := range issues {
		if issue.Reason != "unreadable" {
			continue
		}
		prefix := filepath.Clean(issue.Path)
		for path, item := range previous {
			if path == prefix || strings.HasPrefix(path, prefix+string(filepath.Separator)) {
				if _, exists := current[path]; !exists {
					current[path] = item
				}
			}
		}
	}
}

func coverageEvent(now time.Time, generation uint64, issues []scanIssue, limited bool, summary string, severity domain.Severity) domain.Event {
	samples := issues
	if len(samples) > maxIssueSamples {
		samples = samples[:maxIssueSamples]
	}
	evidence := map[string]any{
		"issue_count": len(issues),
		"issues":      samples,
		"read_only":   true,
	}
	if limited {
		evidence["scan_limited"] = true
	}
	return simpleEvent("file.integrity.coverage_limited", severity, summary, now, generation, evidence)
}

func simpleEvent(kind string, severity domain.Severity, summary string, now time.Time, generation uint64, evidence map[string]any) domain.Event {
	digestInput, _ := json.Marshal(struct {
		Kind       string         `json:"kind"`
		Generation uint64         `json:"generation"`
		Evidence   map[string]any `json:"evidence"`
	}{kind, generation, evidence})
	digest := sha256.Sum256(digestInput)
	return domain.Event{
		ID:         "evt_fim_" + hex.EncodeToString(digest[:12]),
		Kind:       kind,
		Severity:   severity,
		Summary:    summary,
		OccurredAt: now,
		Evidence:   evidence,
	}
}

func hashIssues(issues []scanIssue, limited bool) string {
	if len(issues) == 0 && !limited {
		return ""
	}
	encoded, _ := json.Marshal(struct {
		Issues  []scanIssue `json:"issues"`
		Limited bool        `json:"limited"`
	}{issues, limited})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func hashFile(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if written > limit {
		return "", errors.New("file changed beyond configured hash limit")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
