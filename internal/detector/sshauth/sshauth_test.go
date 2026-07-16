package sshauth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeJournal struct {
	baselineCursor string
	records        []JournalRecord
	baselineErr    error
	readErr        error
	baselineCalls  int
	readCalls      int
}

func (journal *fakeJournal) Baseline(context.Context) (string, error) {
	journal.baselineCalls++
	return journal.baselineCursor, journal.baselineErr
}

func (journal *fakeJournal) ReadAfter(context.Context, string, time.Time, int) ([]JournalRecord, bool, error) {
	journal.readCalls++
	return append([]JournalRecord(nil), journal.records...), false, journal.readErr
}

func TestBruteForceAndSuspiciousSuccessAcrossCommittedCursor(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := t.TempDir()
	now := time.Date(2026, 7, 16, 10, 0, 0, 0, time.UTC)
	detector, err := New(Config{StateDir: stateDir, Paths: []string{logPath}, DisableJournal: true, Threshold: 3, Window: 5 * time.Minute, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := detector.Scan(context.Background())
	if err != nil || len(baseline.Events) != 0 {
		t.Fatalf("baseline = %#v, %v", baseline.Events, err)
	}
	if err := baseline.Commit(); err != nil {
		t.Fatal(err)
	}

	appendLog(t, logPath,
		"Jul 16 10:00:01 host sshd[1]: Failed password for invalid user admin from 203.0.113.10 port 40001 ssh2\n"+
			"Jul 16 10:00:02 host sshd[1]: Failed publickey for root from 203.0.113.10 port 40002 ssh2\n"+
			"Jul 16 10:00:03 host sshd[1]: Failed password for root from 203.0.113.10 port 40003 ssh2\n")
	brute, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(brute.Events) != 1 || brute.Events[0].Kind != "ssh.auth.bruteforce" || brute.Events[0].Evidence["attempts"] != 3 {
		t.Fatalf("brute-force events = %#v", brute.Events)
	}
	if err := brute.Commit(); err != nil {
		t.Fatal(err)
	}

	now = now.Add(time.Minute)
	rawSuccess := "Jul 16 10:01:00 host sshd[2]: Accepted publickey for root from 203.0.113.10 port 41000 ssh2\n"
	appendLog(t, logPath, rawSuccess)
	success, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(success.Events) != 1 || success.Events[0].Kind != "ssh.auth.suspicious_success" || success.Events[0].Evidence["preceding_failures"] != 3 {
		t.Fatalf("success events = %#v", success.Events)
	}
	encoded, err := json.Marshal(success.Events[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "sshd[2]") || strings.Contains(string(encoded), "port 41000") {
		t.Fatal("raw SSH log line leaked into event evidence")
	}
	if err := success.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestPartialLineAndGlobalLineLimitResumeWithoutLoss(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := New(Config{StateDir: t.TempDir(), Paths: []string{logPath}, DisableJournal: true, Threshold: 2, MaxLines: 1})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := baseline.Commit(); err != nil {
		t.Fatal(err)
	}

	appendLog(t, logPath, "host sshd[1]: Failed password for root from 2001:db8::5 port 40001 ssh2")
	partial, err := detector.Scan(context.Background())
	if err != nil || len(partial.Events) != 0 {
		t.Fatalf("partial result = %#v, %v", partial.Events, err)
	}
	if err := partial.Commit(); err != nil {
		t.Fatal(err)
	}
	appendLog(t, logPath, "\nhost sshd[2]: Failed password for root from 2001:db8::5 port 40002 ssh2\n")
	first, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Events) != 1 || first.Events[0].Kind != "ssh.auth.coverage_limited" {
		t.Fatalf("first limited batch = %#v", first.Events)
	}
	if err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	second, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	foundBrute := false
	for _, event := range second.Events {
		if event.Kind == "ssh.auth.bruteforce" && event.Evidence["source_ip"] == "2001:db8::5" {
			foundBrute = true
		}
	}
	if !foundBrute {
		t.Fatalf("second batch did not resume at remaining line: %#v", second.Events)
	}
}

func TestRotationAndNewlyCreatedLogAreReadFromBeginning(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	logPath := filepath.Join(root, "auth.log")
	if err := os.WriteFile(logPath, []byte("historical line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	detector, err := New(Config{StateDir: t.TempDir(), Paths: []string{logPath}, DisableJournal: true})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := baseline.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("host sshd[9]: Accepted password for deploy from 192.0.2.44 port 2222 ssh2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(rotated.Events) != 1 || rotated.Events[0].Kind != "ssh.auth.succeeded" {
		t.Fatalf("rotated events = %#v", rotated.Events)
	}

	missingPath := filepath.Join(root, "secure")
	missingDetector, err := New(Config{StateDir: t.TempDir(), Paths: []string{missingPath}, DisableJournal: true})
	if err != nil {
		t.Fatal(err)
	}
	missingBaseline, err := missingDetector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := missingBaseline.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(missingPath, []byte("host sshd[10]: Accepted publickey for ops from 192.0.2.45 port 2223 ssh2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := missingDetector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(created.Events) != 1 || created.Events[0].Kind != "ssh.auth.succeeded" {
		t.Fatalf("new log events = %#v", created.Events)
	}
}

func TestJournalFallbackUsesCursorWithoutHistoricalReplay(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 16, 13, 0, 0, 0, time.UTC)
	journal := &fakeJournal{baselineCursor: "s=baseline"}
	detector, err := New(Config{
		StateDir: t.TempDir(), Paths: []string{filepath.Join(t.TempDir(), "missing-auth.log")},
		Journal: journal, Threshold: 2, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := detector.Scan(context.Background())
	if err != nil || len(baseline.Events) != 0 || journal.baselineCalls != 1 || journal.readCalls != 0 {
		t.Fatalf("journal baseline = %#v, calls=%d/%d, err=%v", baseline.Events, journal.baselineCalls, journal.readCalls, err)
	}
	if err := baseline.Commit(); err != nil {
		t.Fatal(err)
	}

	journal.records = []JournalRecord{
		{Cursor: "s=one", Message: "sshd[1]: Failed password for root from 203.0.113.55 port 50001 ssh2"},
		{Cursor: "s=two", Message: "sshd[2]: Failed password for root from 203.0.113.55 port 50002 ssh2"},
	}
	now = now.Add(time.Minute)
	result, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Events[0].Kind != "ssh.auth.bruteforce" || journal.readCalls != 1 {
		t.Fatalf("journal events = %#v, read calls=%d", result.Events, journal.readCalls)
	}
	if err := result.Commit(); err != nil {
		t.Fatal(err)
	}
	state, exists, err := detector.loadState()
	if err != nil || !exists || state.JournalCursor != "s=two" {
		t.Fatalf("journal state = %#v, %t, %v", state, exists, err)
	}
}

func TestReadableFileSourceTakesPriorityOverJournal(t *testing.T) {
	t.Parallel()
	logPath := filepath.Join(t.TempDir(), "auth.log")
	if err := os.WriteFile(logPath, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	journal := &fakeJournal{baselineCursor: "should-not-be-read"}
	detector, err := New(Config{StateDir: t.TempDir(), Paths: []string{logPath}, Journal: journal})
	if err != nil {
		t.Fatal(err)
	}
	result, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if journal.baselineCalls != 0 || journal.readCalls != 0 {
		t.Fatalf("journal was queried despite readable auth.log: %d/%d", journal.baselineCalls, journal.readCalls)
	}
	if err := result.Commit(); err != nil {
		t.Fatal(err)
	}
}

func appendLog(t *testing.T, path, content string) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(content); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}
