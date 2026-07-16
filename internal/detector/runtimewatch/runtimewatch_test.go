package runtimewatch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

const tcpHeader = "  sl  local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

func TestProcessPIDChurnIsQuietAndPortChangesAreClassified(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSocketTables(t, procRoot, tcpHeader+"   0: 0100007F:0016 00000000:0000 0A 0 0 0 0 0 0\n", tcpHeader)
	writeProcess(t, procRoot, "100", "init", 0)
	now := time.Date(2026, 7, 16, 14, 0, 0, 0, time.UTC)
	detector, err := New(Config{StateDir: t.TempDir(), ProcRoot: procRoot, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	baseline, err := detector.Scan(context.Background())
	if err != nil || len(baseline.Events) != 0 {
		t.Fatalf("baseline events = %#v, %v", baseline.Events, err)
	}
	if err := baseline.Commit(); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(filepath.Join(procRoot, "100")); err != nil {
		t.Fatal(err)
	}
	writeProcess(t, procRoot, "101", "init", 0)
	now = now.Add(time.Minute)
	pidChurn, err := detector.Scan(context.Background())
	if err != nil || len(pidChurn.Events) != 0 {
		t.Fatalf("PID churn events = %#v, %v", pidChurn.Events, err)
	}
	if err := pidChurn.Commit(); err != nil {
		t.Fatal(err)
	}

	writeProcess(t, procRoot, "200", "worker", 1000)
	writeSocketTables(t, procRoot, tcpHeader+"   0: 00000000:1F90 00000000:0000 0A 0 0 0 0 0 0\n", tcpHeader)
	now = now.Add(time.Minute)
	changed, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	foundProcess := false
	foundOpened := false
	foundClosed := false
	for _, event := range changed.Events {
		switch event.Kind {
		case "runtime.process.first_seen":
			foundProcess = event.Evidence["name"] == "worker"
		case "runtime.port.opened":
			foundOpened = event.Evidence["port"] == 8080 && event.Evidence["scope"] == "wildcard" && event.Severity == domain.SeverityHigh
		case "runtime.port.closed":
			foundClosed = event.Evidence["port"] == 22
		}
	}
	if !foundProcess || !foundOpened || !foundClosed {
		t.Fatalf("runtime change events = %#v", changed.Events)
	}
}

func TestExecutableIdentityDriftIsHighSeverity(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	procRoot := filepath.Join(root, "proc")
	writeSocketTables(t, procRoot, tcpHeader, tcpHeader)
	writeProcess(t, procRoot, "300", "api", 1000)
	firstExecutable := filepath.Join(root, "api-v1")
	secondExecutable := filepath.Join(root, "api-v2")
	if err := os.WriteFile(firstExecutable, []byte("v1"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secondExecutable, []byte("v2"), 0o700); err != nil {
		t.Fatal(err)
	}
	exeLink := filepath.Join(procRoot, "300", "exe")
	if err := os.Symlink(firstExecutable, exeLink); err != nil {
		t.Skipf("symbolic links unavailable for proc fixture: %v", err)
	}
	detector, err := New(Config{StateDir: t.TempDir(), ProcRoot: procRoot})
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
	if err := os.Remove(exeLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secondExecutable, exeLink); err != nil {
		t.Fatal(err)
	}
	changed, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range changed.Events {
		if event.Kind == "runtime.process.identity_changed" && event.Severity == domain.SeverityHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("identity drift event missing: %#v", changed.Events)
	}
}

func TestProcessLimitProducesCoverageEventWithoutFalseChanges(t *testing.T) {
	t.Parallel()
	procRoot := t.TempDir()
	writeSocketTables(t, procRoot, tcpHeader, tcpHeader)
	writeProcess(t, procRoot, "1", "one", 0)
	writeProcess(t, procRoot, "2", "two", 0)
	detector, err := New(Config{StateDir: t.TempDir(), ProcRoot: procRoot, MaxProcesses: 1, MaxKnown: 1})
	if err != nil {
		t.Fatal(err)
	}
	result, err := detector.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Events) != 1 || result.Events[0].Kind != "runtime.coverage_limited" {
		t.Fatalf("limited events = %#v", result.Events)
	}
}

func TestAddressScopeRecognizesIPv4LoopbackRange(t *testing.T) {
	t.Parallel()
	ports, limited := parseListeningPorts([]byte(tcpHeader+
		"0: 0200007F:0050 00000000:0000 0A\n"+
		"1: 00000000:01BB 00000000:0000 0A\n"), "tcp4", 10)
	if limited || len(ports) != 2 {
		t.Fatalf("ports = %#v, limited=%t", ports, limited)
	}
	for _, port := range ports {
		if port.Port == 80 && port.Scope != "loopback" {
			t.Fatalf("127/8 scope = %s", port.Scope)
		}
		if port.Port == 443 && port.Scope != "wildcard" {
			t.Fatalf("wildcard scope = %s", port.Scope)
		}
	}
}

func writeSocketTables(t *testing.T, procRoot, tcp4, tcp6 string) {
	t.Helper()
	directory := filepath.Join(procRoot, "net")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tcp"), []byte(tcp4), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "tcp6"), []byte(tcp6), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeProcess(t *testing.T, procRoot, pid, name string, uid uint32) {
	t.Helper()
	directory := filepath.Join(procRoot, pid)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	content := "Name:\t" + name + "\nUid:\t" + fmt.Sprint(uid) + "\t" + fmt.Sprint(uid) + "\t" + fmt.Sprint(uid) + "\t" + fmt.Sprint(uid) + "\n"
	if err := os.WriteFile(filepath.Join(directory, "status"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
