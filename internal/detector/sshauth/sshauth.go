package sshauth

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

const (
	stateSchemaVersion = 1
	stateFilename      = "ssh-auth-state.json"
	defaultMaxRead     = int64(4 << 20)
	defaultMaxLines    = 5000
	maxLineBytes       = 16 << 10
	maxStateBytes      = int64(4 << 20)
	prefixLimit        = int64(4096)
	maxFailureIPs      = 4096
	maxAttemptsPerIP   = 100
	maxIssueSamples    = 20
)

var (
	failedPattern      = regexp.MustCompile(`Failed (password|publickey|keyboard-interactive(?:/pam)?) for (invalid user )?([^ ]{1,128}) from ([^ ]+) port [0-9]+`)
	acceptedPattern    = regexp.MustCompile(`Accepted (password|publickey|keyboard-interactive(?:/pam)?) for ([^ ]{1,128}) from ([^ ]+) port [0-9]+`)
	maxAttemptsPattern = regexp.MustCompile(`maximum authentication attempts exceeded for (invalid user )?([^ ]{1,128}) from ([^ ]+) port [0-9]+`)
)

type Config struct {
	StateDir       string
	Paths          []string
	Now            func() time.Time
	Journal        JournalSource
	DisableJournal bool
	Threshold      int
	Window         time.Duration
	MaxRead        int64
	MaxLines       int
}

type Detector struct {
	config  Config
	journal JournalSource
}

type JournalRecord struct {
	Cursor  string
	Message string
}

type JournalSource interface {
	Baseline(context.Context) (string, error)
	ReadAfter(context.Context, string, time.Time, int) ([]JournalRecord, bool, error)
}

type Result struct {
	Events []domain.Event
	Commit func() error
}

type fileCursor struct {
	Exists      bool   `json:"exists"`
	Offset      int64  `json:"offset"`
	PrefixBytes int64  `json:"prefix_bytes"`
	PrefixHash  string `json:"prefix_sha256,omitempty"`
}

type failure struct {
	At          int64  `json:"at_unix_nano"`
	User        string `json:"user"`
	InvalidUser bool   `json:"invalid_user,omitempty"`
}

type detectorState struct {
	SchemaVersion      int                   `json:"schema_version"`
	Generation         uint64                `json:"generation"`
	CoverageHash       string                `json:"coverage_hash,omitempty"`
	Files              map[string]fileCursor `json:"files"`
	Failures           map[string][]failure  `json:"failures"`
	AlertedUntil       map[string]int64      `json:"alerted_until"`
	JournalInitialized bool                  `json:"journal_initialized,omitempty"`
	JournalCursor      string                `json:"journal_cursor,omitempty"`
	JournalSince       int64                 `json:"journal_since_unix_nano,omitempty"`
}

type issue struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
}

type logLine struct {
	path   string
	offset int64
	text   string
	key    string
}

type authRecord struct {
	success     bool
	method      string
	user        string
	invalidUser bool
	sourceIP    string
	key         string
}

func New(config Config) (*Detector, error) {
	if strings.TrimSpace(config.StateDir) == "" {
		return nil, errors.New("SSH auth state directory is required")
	}
	stateDir, err := filepath.Abs(config.StateDir)
	if err != nil {
		return nil, fmt.Errorf("resolve SSH auth state directory: %w", err)
	}
	config.StateDir = stateDir
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Threshold == 0 {
		config.Threshold = 5
	}
	if config.Threshold < 2 || config.Threshold > 100 {
		return nil, errors.New("SSH brute-force threshold must be between 2 and 100")
	}
	if config.Window == 0 {
		config.Window = 5 * time.Minute
	}
	if config.Window < 10*time.Second || config.Window > 24*time.Hour {
		return nil, errors.New("SSH brute-force window must be between 10 seconds and 24 hours")
	}
	if config.MaxRead == 0 {
		config.MaxRead = defaultMaxRead
	}
	if config.MaxRead < 4096 || config.MaxRead > 64<<20 {
		return nil, errors.New("SSH auth max read must be between 4 KiB and 64 MiB")
	}
	if config.MaxLines == 0 {
		config.MaxLines = defaultMaxLines
	}
	if config.MaxLines < 1 || config.MaxLines > 100_000 {
		return nil, errors.New("SSH auth max lines must be between 1 and 100000")
	}
	if len(config.Paths) > 16 {
		return nil, errors.New("SSH auth supports at most 16 log paths")
	}
	seen := make(map[string]bool, len(config.Paths))
	paths := make([]string, 0, len(config.Paths))
	for _, raw := range config.Paths {
		if strings.TrimSpace(raw) == "" || strings.ContainsAny(raw, "\x00\r\n") {
			return nil, errors.New("SSH auth log path is invalid")
		}
		path, err := filepath.Abs(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("resolve SSH auth log path: %w", err)
		}
		path = filepath.Clean(path)
		if !seen[path] {
			seen[path] = true
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	config.Paths = paths
	journal := config.Journal
	if journal == nil && runtime.GOOS == "linux" && !config.DisableJournal {
		journal = SystemdJournal{}
	}
	return &Detector{config: config, journal: journal}, nil
}

func DefaultPaths() []string {
	if runtime.GOOS != "linux" {
		return nil
	}
	return []string{"/var/log/auth.log", "/var/log/secure"}
}

func (detector *Detector) Scan(ctx context.Context) (Result, error) {
	previous, exists, err := detector.loadState()
	if err != nil {
		return Result{}, err
	}
	now := detector.config.Now().UTC()
	if exists && previous.Generation == ^uint64(0) {
		return Result{}, errors.New("SSH auth state generation is exhausted")
	}
	next := cloneState(previous)
	if !exists {
		next = detectorState{
			SchemaVersion: stateSchemaVersion,
			Generation:    1,
			Files:         make(map[string]fileCursor),
			Failures:      make(map[string][]failure),
			AlertedUntil:  make(map[string]int64),
		}
	} else {
		next.Generation++
	}

	lines := make([]logLine, 0)
	issues := make([]issue, 0)
	usableFileSource := false
	for _, path := range detector.config.Paths {
		if err := ctx.Err(); err != nil {
			return Result{}, err
		}
		oldCursor := previous.Files[path]
		remainingLines := detector.config.MaxLines - len(lines)
		if remainingLines <= 0 {
			next.Files[path] = oldCursor
			issues = append(issues, issue{Path: path, Reason: "line_limit_reached"})
			continue
		}
		cursor, fileLines, fileIssues, readable := detector.readPath(path, oldCursor, exists, remainingLines)
		next.Files[path] = cursor
		usableFileSource = usableFileSource || readable
		lines = append(lines, fileLines...)
		issues = append(issues, fileIssues...)
	}
	if usableFileSource {
		next.JournalInitialized = false
		next.JournalCursor = ""
		next.JournalSince = 0
	} else if detector.journal != nil {
		journalLines, journalIssues := detector.readJournal(ctx, previous, &next, now, detector.config.MaxLines-len(lines))
		lines = append(lines, journalLines...)
		issues = append(issues, journalIssues...)
	}
	pruneFailures(&next, now, now.Add(-detector.config.Window))
	events := make([]domain.Event, 0)
	for _, line := range lines {
		record, ok := parseAuthLine(line)
		if !ok {
			continue
		}
		events = append(events, detector.applyRecord(&next, record, now, previous.Generation)...)
	}

	sort.Slice(issues, func(i, j int) bool {
		if issues[i].Path == issues[j].Path {
			return issues[i].Reason < issues[j].Reason
		}
		return issues[i].Path < issues[j].Path
	})
	coverageHash := hashValue(issues)
	if coverageHash != previous.CoverageHash {
		switch {
		case len(issues) > 0:
			events = append(events, sshEvent("ssh.auth.coverage_limited", domain.SeverityMedium, "SSH authentication log coverage is limited", now, previous.Generation, "coverage:"+coverageHash, coverageEvidence(issues)))
		case exists && previous.CoverageHash != "":
			events = append(events, sshEvent("ssh.auth.coverage_restored", domain.SeverityInfo, "SSH authentication log coverage was restored", now, previous.Generation, "coverage-restored", map[string]any{"read_only": true}))
		}
	}
	next.CoverageHash = coverageHash

	return Result{Events: events, Commit: func() error { return detector.saveState(next) }}, nil
}

func (detector *Detector) readPath(path string, previous fileCursor, stateExists bool, maxLines int) (fileCursor, []logLine, []issue, bool) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return fileCursor{Exists: false}, nil, nil, false
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return previous, nil, []issue{{Path: path, Reason: "unreadable_or_unsafe"}}, false
	}
	prefixBytes := previous.PrefixBytes
	if !previous.Exists || prefixBytes == 0 {
		prefixBytes = minInt64(info.Size(), prefixLimit)
	}
	prefixHash, err := hashPrefix(path, prefixBytes)
	if err != nil {
		return previous, nil, []issue{{Path: path, Reason: "unreadable"}}, false
	}

	offset := previous.Offset
	if !stateExists {
		offset = info.Size()
	} else if !previous.Exists {
		offset = 0
		prefixBytes = minInt64(info.Size(), prefixLimit)
		prefixHash, err = hashPrefix(path, prefixBytes)
		if err != nil {
			return previous, nil, []issue{{Path: path, Reason: "unreadable"}}, false
		}
	} else if info.Size() < previous.Offset || previous.PrefixHash != prefixHash {
		offset = 0
		prefixBytes = minInt64(info.Size(), prefixLimit)
		prefixHash, err = hashPrefix(path, prefixBytes)
		if err != nil {
			return previous, nil, []issue{{Path: path, Reason: "unreadable"}}, false
		}
	}

	lines, nextOffset, limited, oversized, err := detector.readLines(path, offset, maxLines)
	if err != nil {
		return previous, nil, []issue{{Path: path, Reason: "unreadable"}}, false
	}
	issues := make([]issue, 0, 2)
	if limited {
		issues = append(issues, issue{Path: path, Reason: "read_limit_reached"})
	}
	if oversized {
		issues = append(issues, issue{Path: path, Reason: "oversized_line_skipped"})
	}
	return fileCursor{Exists: true, Offset: nextOffset, PrefixBytes: prefixBytes, PrefixHash: prefixHash}, lines, issues, true
}

func (detector *Detector) readJournal(ctx context.Context, previous detectorState, next *detectorState, now time.Time, maxLines int) ([]logLine, []issue) {
	if maxLines <= 0 {
		return nil, []issue{{Path: "systemd-journal", Reason: "line_limit_reached"}}
	}
	if !previous.JournalInitialized {
		cursor, err := detector.journal.Baseline(ctx)
		if err != nil {
			return nil, []issue{{Path: "systemd-journal", Reason: "unavailable"}}
		}
		next.JournalInitialized = true
		next.JournalCursor = cursor
		next.JournalSince = now.UnixNano()
		return nil, nil
	}
	records, limited, err := detector.journal.ReadAfter(ctx, previous.JournalCursor, time.Unix(0, previous.JournalSince), maxLines)
	if err != nil {
		cursor, baselineErr := detector.journal.Baseline(ctx)
		if baselineErr == nil {
			next.JournalInitialized = true
			next.JournalCursor = cursor
			next.JournalSince = now.UnixNano()
		}
		return nil, []issue{{Path: "systemd-journal", Reason: "cursor_unavailable"}}
	}
	lines := make([]logLine, 0, len(records))
	for _, record := range records {
		if !validJournalCursor(record.Cursor) || len(record.Message) > maxLineBytes {
			continue
		}
		lines = append(lines, logLine{path: "systemd-journal", text: record.Message, key: record.Cursor})
		next.JournalCursor = record.Cursor
	}
	issues := make([]issue, 0, 1)
	if limited {
		issues = append(issues, issue{Path: "systemd-journal", Reason: "read_limit_reached"})
	}
	return lines, issues
}

func (detector *Detector) readLines(path string, offset int64, maxLines int) ([]logLine, int64, bool, bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, offset, false, false, err
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return nil, offset, false, false, err
	}
	content, err := io.ReadAll(io.LimitReader(file, detector.config.MaxRead+1))
	if err != nil {
		return nil, offset, false, false, err
	}
	limited := int64(len(content)) > detector.config.MaxRead
	if limited {
		content = content[:detector.config.MaxRead]
	}
	lastNewline := bytes.LastIndexByte(content, '\n')
	if lastNewline < 0 {
		if limited {
			return nil, offset + int64(len(content)), true, true, nil
		}
		return nil, offset, false, false, nil
	}
	complete := content[:lastNewline+1]
	nextOffset := offset + int64(len(complete))
	parts := bytes.Split(complete, []byte{'\n'})
	lines := make([]logLine, 0, minInt(len(parts), maxLines))
	lineOffset := offset
	oversized := false
	for _, part := range parts[:len(parts)-1] {
		lineLength := int64(len(part) + 1)
		if len(part) > maxLineBytes {
			oversized = true
		} else if len(lines) < maxLines {
			lines = append(lines, logLine{path: path, offset: lineOffset, text: string(part)})
		} else {
			limited = true
			nextOffset = lineOffset
			break
		}
		lineOffset += lineLength
	}
	return lines, nextOffset, limited, oversized, nil
}

func parseAuthLine(line logLine) (authRecord, bool) {
	if match := failedPattern.FindStringSubmatch(line.text); len(match) == 5 {
		if !validUser(match[3]) {
			return authRecord{}, false
		}
		ip, ok := normalizedIP(match[4])
		if !ok {
			return authRecord{}, false
		}
		return authRecord{method: normalizeMethod(match[1]), user: match[3], invalidUser: match[2] != "", sourceIP: ip, key: lineKey(line)}, true
	}
	if match := acceptedPattern.FindStringSubmatch(line.text); len(match) == 4 {
		if !validUser(match[2]) {
			return authRecord{}, false
		}
		ip, ok := normalizedIP(match[3])
		if !ok {
			return authRecord{}, false
		}
		return authRecord{success: true, method: normalizeMethod(match[1]), user: match[2], sourceIP: ip, key: lineKey(line)}, true
	}
	if match := maxAttemptsPattern.FindStringSubmatch(line.text); len(match) == 4 {
		if !validUser(match[2]) {
			return authRecord{}, false
		}
		ip, ok := normalizedIP(match[3])
		if !ok {
			return authRecord{}, false
		}
		return authRecord{method: "maximum_attempts", user: match[2], invalidUser: match[1] != "", sourceIP: ip, key: lineKey(line)}, true
	}
	return authRecord{}, false
}

func (detector *Detector) applyRecord(state *detectorState, record authRecord, now time.Time, generation uint64) []domain.Event {
	if record.success {
		preceding := state.Failures[record.sourceIP]
		severity := domain.SeverityLow
		kind := "ssh.auth.succeeded"
		summary := "SSH authentication succeeded"
		if len(preceding) >= 3 {
			severity = domain.SeverityHigh
			kind = "ssh.auth.suspicious_success"
			summary = "SSH authentication succeeded after repeated failures"
		}
		delete(state.Failures, record.sourceIP)
		delete(state.AlertedUntil, record.sourceIP)
		return []domain.Event{sshEvent(kind, severity, summary, now, generation, record.key, map[string]any{
			"source_ip": record.sourceIP, "user": record.user, "method": record.method,
			"preceding_failures": len(preceding), "read_only": true,
		})}
	}

	attempts := append(state.Failures[record.sourceIP], failure{At: now.UnixNano(), User: record.user, InvalidUser: record.invalidUser})
	if len(attempts) > maxAttemptsPerIP {
		attempts = attempts[len(attempts)-maxAttemptsPerIP:]
	}
	state.Failures[record.sourceIP] = attempts
	if len(state.Failures) > maxFailureIPs {
		pruneOldestIP(state.Failures, state.AlertedUntil)
	}
	if len(attempts) < detector.config.Threshold || state.AlertedUntil[record.sourceIP] > now.UnixNano() {
		return nil
	}
	state.AlertedUntil[record.sourceIP] = now.Add(detector.config.Window).UnixNano()
	users := make(map[string]bool)
	invalidAttempts := 0
	for _, attempt := range attempts {
		users[attempt.User] = true
		if attempt.InvalidUser {
			invalidAttempts++
		}
	}
	return []domain.Event{sshEvent("ssh.auth.bruteforce", domain.SeverityHigh, "Repeated SSH authentication failures crossed the threshold", now, generation, record.sourceIP+":"+record.key, map[string]any{
		"source_ip": record.sourceIP, "attempts": len(attempts), "unique_users": len(users),
		"invalid_user_attempts": invalidAttempts, "window_seconds": int(detector.config.Window.Seconds()), "read_only": true,
	})}
}

func cloneState(value detectorState) detectorState {
	copyValue := detectorState{
		SchemaVersion:      value.SchemaVersion,
		Generation:         value.Generation,
		CoverageHash:       value.CoverageHash,
		Files:              make(map[string]fileCursor, len(value.Files)),
		Failures:           make(map[string][]failure, len(value.Failures)),
		AlertedUntil:       make(map[string]int64, len(value.AlertedUntil)),
		JournalInitialized: value.JournalInitialized,
		JournalCursor:      value.JournalCursor,
		JournalSince:       value.JournalSince,
	}
	for path, cursor := range value.Files {
		copyValue.Files[path] = cursor
	}
	for ip, attempts := range value.Failures {
		copyValue.Failures[ip] = append([]failure(nil), attempts...)
	}
	for ip, until := range value.AlertedUntil {
		copyValue.AlertedUntil[ip] = until
	}
	return copyValue
}

func pruneFailures(state *detectorState, now, cutoff time.Time) {
	for ip, attempts := range state.Failures {
		kept := attempts[:0]
		for _, attempt := range attempts {
			if attempt.At >= cutoff.UnixNano() {
				kept = append(kept, attempt)
			}
		}
		if len(kept) == 0 {
			delete(state.Failures, ip)
			if state.AlertedUntil[ip] <= now.UnixNano() {
				delete(state.AlertedUntil, ip)
			}
		} else {
			state.Failures[ip] = kept
		}
	}
}

func pruneOldestIP(failures map[string][]failure, alerted map[string]int64) {
	oldestIP := ""
	oldest := int64(^uint64(0) >> 1)
	for ip, attempts := range failures {
		if len(attempts) > 0 && attempts[len(attempts)-1].At < oldest {
			oldest = attempts[len(attempts)-1].At
			oldestIP = ip
		}
	}
	if oldestIP != "" {
		delete(failures, oldestIP)
		delete(alerted, oldestIP)
	}
}

func (detector *Detector) loadState() (detectorState, bool, error) {
	path := filepath.Join(detector.config.StateDir, "detectors", stateFilename)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return detectorState{}, false, nil
	}
	if err != nil {
		return detectorState{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxStateBytes {
		return detectorState{}, false, errors.New("SSH auth state must be a small regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return detectorState{}, false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(bufio.NewReader(io.LimitReader(file, maxStateBytes+1)))
	decoder.DisallowUnknownFields()
	var value detectorState
	if err := decoder.Decode(&value); err != nil {
		return detectorState{}, false, fmt.Errorf("decode SSH auth state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return detectorState{}, false, errors.New("SSH auth state contains trailing JSON")
	}
	if err := validateState(value); err != nil {
		return detectorState{}, false, err
	}
	return value, true, nil
}

func (detector *Detector) saveState(value detectorState) error {
	if err := validateState(value); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > maxStateBytes {
		return errors.New("SSH auth state exceeds size limit")
	}
	directory := filepath.Join(detector.config.StateDir, "detectors")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".ssh-auth-*.tmp")
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
	if err := os.Rename(temporaryPath, filepath.Join(directory, stateFilename)); err != nil {
		return err
	}
	completed = true
	return nil
}

func validateState(value detectorState) error {
	if value.SchemaVersion != stateSchemaVersion || value.Generation == 0 {
		return errors.New("SSH auth state has an unsupported schema or generation")
	}
	if value.Files == nil || len(value.Files) > 16 || value.Failures == nil || value.AlertedUntil == nil || len(value.Failures) > maxFailureIPs {
		return errors.New("SSH auth state has invalid collections")
	}
	for path, cursor := range value.Files {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || cursor.Offset < 0 || cursor.PrefixBytes < 0 || cursor.PrefixBytes > prefixLimit {
			return errors.New("SSH auth state has an invalid file cursor")
		}
		if cursor.PrefixHash != "" && !validSHA256(cursor.PrefixHash) {
			return errors.New("SSH auth state has an invalid prefix hash")
		}
	}
	for ip, attempts := range value.Failures {
		if parsed := net.ParseIP(ip); parsed == nil || len(attempts) > maxAttemptsPerIP {
			return errors.New("SSH auth state has invalid failure history")
		}
		for _, attempt := range attempts {
			if attempt.At <= 0 || !validUser(attempt.User) {
				return errors.New("SSH auth state has an invalid failure attempt")
			}
		}
	}
	for ip, until := range value.AlertedUntil {
		if net.ParseIP(ip) == nil || until < 0 {
			return errors.New("SSH auth state has invalid alert suppression")
		}
	}
	if value.JournalInitialized {
		if value.JournalSince <= 0 || !validJournalCursor(value.JournalCursor) {
			return errors.New("SSH auth state has an invalid journal cursor")
		}
	} else if value.JournalCursor != "" || value.JournalSince != 0 {
		return errors.New("SSH auth state has inconsistent journal state")
	}
	return nil
}

func sshEvent(kind string, severity domain.Severity, summary string, now time.Time, generation uint64, key string, evidence map[string]any) domain.Event {
	digest := sha256.Sum256([]byte(kind + "\x00" + strconv.FormatUint(generation, 10) + "\x00" + key))
	return domain.Event{ID: "evt_ssh_" + hex.EncodeToString(digest[:12]), Kind: kind, Severity: severity, Summary: summary, OccurredAt: now, Evidence: evidence}
}

func coverageEvidence(issues []issue) map[string]any {
	samples := issues
	if len(samples) > maxIssueSamples {
		samples = samples[:maxIssueSamples]
	}
	return map[string]any{"issue_count": len(issues), "issues": samples, "read_only": true}
}

func hashPrefix(path string, size int64) (string, error) {
	if size == 0 {
		return "", nil
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	written, err := io.CopyN(hash, file, size)
	if err != nil || written != size {
		return "", errors.New("read SSH auth log prefix")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func normalizedIP(raw string) (string, bool) {
	value := strings.Trim(raw, "[]")
	parsed := net.ParseIP(value)
	if parsed == nil {
		return "", false
	}
	return parsed.String(), true
}

func normalizeMethod(value string) string {
	return strings.TrimSuffix(value, "/pam")
}

func validUser(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\x00\r\n\t ")
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func lineKey(line logLine) string {
	if line.key != "" {
		return line.path + ":" + line.key
	}
	digest := sha256.Sum256([]byte(line.text))
	return line.path + ":" + strconv.FormatInt(line.offset, 10) + ":" + hex.EncodeToString(digest[:8])
}

func validJournalCursor(value string) bool {
	return len(value) <= 1024 && !strings.ContainsAny(value, "\x00\r\n")
}

func hashValue(value any) string {
	encoded, _ := json.Marshal(value)
	if string(encoded) == "[]" || string(encoded) == "null" {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func minInt64(left, right int64) int64 {
	if left < right {
		return left
	}
	return right
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
