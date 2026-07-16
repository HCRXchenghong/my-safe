package runtimewatch

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
	"strconv"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

const (
	stateSchemaVersion  = 1
	stateFilename       = "runtime-watch-state.json"
	defaultMaxProcesses = 20_000
	defaultMaxKnown     = 50_000
	defaultMaxEvents    = 500
	defaultMaxPorts     = 100_000
	maxStateBytes       = int64(16 << 20)
	maxStatusBytes      = int64(64 << 10)
	maxSocketTableBytes = int64(32 << 20)
	maxIssueSamples     = 20
)

type Config struct {
	StateDir     string
	ProcRoot     string
	Now          func() time.Time
	MaxProcesses int
	MaxKnown     int
	MaxEvents    int
	MaxPorts     int
}

type Detector struct {
	config Config
}

type Result struct {
	Events []domain.Event
	Commit func() error
}

type processEntry struct {
	Identity   string `json:"identity"`
	Name       string `json:"name"`
	UID        uint32 `json:"uid"`
	Executable string `json:"executable,omitempty"`
	LastSeen   uint64 `json:"last_seen_generation"`
}

type portEntry struct {
	Key      string `json:"key"`
	Family   string `json:"family"`
	Port     int    `json:"port"`
	Scope    string `json:"scope"`
	Protocol string `json:"protocol"`
}

type detectorState struct {
	SchemaVersion int                     `json:"schema_version"`
	Generation    uint64                  `json:"generation"`
	CoverageHash  string                  `json:"coverage_hash,omitempty"`
	Known         map[string]processEntry `json:"known_processes"`
	Names         map[string]string       `json:"process_names"`
	Ports         map[string]portEntry    `json:"listening_ports"`
}

type issue struct {
	Area   string `json:"area"`
	Reason string `json:"reason"`
}

type captureResult struct {
	processes       map[string]processEntry
	ports           map[string]portEntry
	processComplete bool
	familyComplete  map[string]bool
	issues          []issue
}

func New(config Config) (*Detector, error) {
	if strings.TrimSpace(config.StateDir) == "" {
		return nil, errors.New("runtime watch state directory is required")
	}
	stateDir, err := filepath.Abs(config.StateDir)
	if err != nil {
		return nil, fmt.Errorf("resolve runtime watch state directory: %w", err)
	}
	config.StateDir = stateDir
	if config.ProcRoot == "" {
		config.ProcRoot = "/proc"
	}
	procRoot, err := filepath.Abs(config.ProcRoot)
	if err != nil {
		return nil, fmt.Errorf("resolve proc root: %w", err)
	}
	config.ProcRoot = procRoot
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.MaxProcesses == 0 {
		config.MaxProcesses = defaultMaxProcesses
	}
	if config.MaxProcesses < 1 || config.MaxProcesses > 200_000 {
		return nil, errors.New("runtime watch max processes must be between 1 and 200000")
	}
	if config.MaxKnown == 0 {
		config.MaxKnown = defaultMaxKnown
	}
	if config.MaxKnown < config.MaxProcesses || config.MaxKnown > 500_000 {
		return nil, errors.New("runtime watch max known processes must cover max processes and not exceed 500000")
	}
	if config.MaxEvents == 0 {
		config.MaxEvents = defaultMaxEvents
	}
	if config.MaxEvents < 1 || config.MaxEvents > 5000 {
		return nil, errors.New("runtime watch max events must be between 1 and 5000")
	}
	if config.MaxPorts == 0 {
		config.MaxPorts = defaultMaxPorts
	}
	if config.MaxPorts < 1 || config.MaxPorts > 1_000_000 {
		return nil, errors.New("runtime watch max ports must be between 1 and 1000000")
	}
	return &Detector{config: config}, nil
}

func DefaultEnabled() bool {
	return runtime.GOOS == "linux"
}

func (detector *Detector) Scan(ctx context.Context) (Result, error) {
	previous, exists, err := detector.loadState()
	if err != nil {
		return Result{}, err
	}
	if exists && previous.Generation == ^uint64(0) {
		return Result{}, errors.New("runtime watch state generation is exhausted")
	}
	captured, err := detector.capture(ctx)
	if err != nil {
		return Result{}, err
	}
	now := detector.config.Now().UTC()
	nextGeneration := uint64(1)
	if exists {
		nextGeneration = previous.Generation + 1
	}
	next := cloneState(previous)
	if !exists {
		next = detectorState{
			SchemaVersion: stateSchemaVersion,
			Generation:    nextGeneration,
			Known:         make(map[string]processEntry),
			Names:         make(map[string]string),
			Ports:         make(map[string]portEntry),
		}
	} else {
		next.Generation = nextGeneration
	}
	events := make([]domain.Event, 0)

	if captured.processComplete {
		currentNames := make(map[string]string)
		for identity, process := range captured.processes {
			process.LastSeen = nextGeneration
			if _, known := previous.Known[identity]; !known && exists {
				events = appendBounded(events, detector.config.MaxEvents, processEvent(process, now, previous.Generation, "first_seen"))
			}
			next.Known[identity] = process
			nameKey := strconv.FormatUint(uint64(process.UID), 10) + ":" + process.Name
			if selected, ok := currentNames[nameKey]; !ok || identity < selected {
				currentNames[nameKey] = identity
			}
		}
		if exists {
			for nameKey, identity := range currentNames {
				if oldIdentity := previous.Names[nameKey]; oldIdentity != "" && oldIdentity != identity {
					process := captured.processes[identity]
					events = appendBounded(events, detector.config.MaxEvents, processDriftEvent(process, oldIdentity, now, previous.Generation))
				}
			}
		}
		next.Names = currentNames
		pruneKnown(next.Known, captured.processes, detector.config.MaxKnown)
	}

	for _, family := range []string{"tcp4", "tcp6"} {
		if captured.familyComplete[family] {
			continue
		}
		for key, port := range previous.Ports {
			if port.Family == family {
				captured.ports[key] = port
			}
		}
	}
	if exists {
		portKeys := unionKeys(previous.Ports, captured.ports)
		for _, key := range portKeys {
			before, hadBefore := previous.Ports[key]
			after, hasAfter := captured.ports[key]
			switch {
			case !hadBefore && hasAfter:
				events = appendBounded(events, detector.config.MaxEvents, portEvent(after, true, now, previous.Generation))
			case hadBefore && !hasAfter:
				events = appendBounded(events, detector.config.MaxEvents, portEvent(before, false, now, previous.Generation))
			}
		}
	}
	next.Ports = captured.ports

	sort.Slice(captured.issues, func(i, j int) bool {
		if captured.issues[i].Area == captured.issues[j].Area {
			return captured.issues[i].Reason < captured.issues[j].Reason
		}
		return captured.issues[i].Area < captured.issues[j].Area
	})
	coverageHash := hashValue(captured.issues)
	if coverageHash != previous.CoverageHash {
		switch {
		case len(captured.issues) > 0:
			events = appendBounded(events, detector.config.MaxEvents+1, runtimeEvent("runtime.coverage_limited", domain.SeverityMedium, "Runtime process or port coverage is limited", now, previous.Generation, "coverage:"+coverageHash, coverageEvidence(captured.issues)))
		case exists && previous.CoverageHash != "":
			events = appendBounded(events, detector.config.MaxEvents+1, runtimeEvent("runtime.coverage_restored", domain.SeverityInfo, "Runtime process and port coverage was restored", now, previous.Generation, "coverage-restored", map[string]any{"read_only": true}))
		}
	}
	next.CoverageHash = coverageHash
	if len(events) >= detector.config.MaxEvents {
		events = append(events, runtimeEvent("runtime.change_overflow", domain.SeverityHigh, "Runtime changes reached the per-cycle event limit", now, previous.Generation, "overflow", map[string]any{"event_limit": detector.config.MaxEvents, "read_only": true}))
	}

	return Result{Events: events, Commit: func() error { return detector.saveState(next) }}, nil
}

func (detector *Detector) capture(ctx context.Context) (captureResult, error) {
	result := captureResult{
		processes:      make(map[string]processEntry),
		ports:          make(map[string]portEntry),
		familyComplete: make(map[string]bool),
	}
	entries, err := os.ReadDir(detector.config.ProcRoot)
	if err != nil {
		result.issues = append(result.issues, issue{Area: "processes", Reason: "proc_unreadable"})
	} else {
		result.processComplete = true
		processCount := 0
		for _, item := range entries {
			if err := ctx.Err(); err != nil {
				return captureResult{}, err
			}
			if !item.IsDir() || !numeric(item.Name()) {
				continue
			}
			processCount++
			if processCount > detector.config.MaxProcesses {
				result.processComplete = false
				result.issues = append(result.issues, issue{Area: "processes", Reason: "process_limit_exceeded"})
				break
			}
			process, ok := detector.readProcess(item.Name())
			if ok {
				result.processes[process.Identity] = process
			}
		}
	}

	for _, source := range []struct {
		family string
		path   string
	}{
		{"tcp4", filepath.Join(detector.config.ProcRoot, "net", "tcp")},
		{"tcp6", filepath.Join(detector.config.ProcRoot, "net", "tcp6")},
	} {
		content, err := readLimitedFile(source.path, maxSocketTableBytes)
		if errors.Is(err, os.ErrNotExist) && source.family == "tcp6" {
			result.familyComplete[source.family] = true
			continue
		}
		if err != nil {
			result.issues = append(result.issues, issue{Area: source.family, Reason: "socket_table_unreadable"})
			continue
		}
		ports, limited := parseListeningPorts(content, source.family, detector.config.MaxPorts)
		result.familyComplete[source.family] = !limited
		if limited {
			result.issues = append(result.issues, issue{Area: source.family, Reason: "socket_limit_exceeded"})
		}
		for key, port := range ports {
			result.ports[key] = port
		}
	}
	return result, nil
}

func (detector *Detector) readProcess(pid string) (processEntry, bool) {
	statusPath := filepath.Join(detector.config.ProcRoot, pid, "status")
	file, err := os.Open(statusPath)
	if err != nil {
		return processEntry{}, false
	}
	defer file.Close()
	reader := bufio.NewScanner(io.LimitReader(file, maxStatusBytes))
	name := ""
	uid := uint64(0)
	hasUID := false
	for reader.Scan() {
		line := reader.Text()
		if value, found := strings.CutPrefix(line, "Name:\t"); found {
			name = strings.TrimSpace(value)
		}
		if value, found := strings.CutPrefix(line, "Uid:\t"); found {
			fields := strings.Fields(value)
			if len(fields) > 0 {
				parsed, err := strconv.ParseUint(fields[0], 10, 32)
				if err == nil {
					uid = parsed
					hasUID = true
				}
			}
		}
	}
	if !validProcessName(name) || !hasUID {
		return processEntry{}, false
	}
	executable := ""
	if target, err := os.Readlink(filepath.Join(detector.config.ProcRoot, pid, "exe")); err == nil && validExecutable(target) {
		executable = target
	}
	identityMaterial := executable
	if identityMaterial == "" {
		identityMaterial = "name:" + name
	}
	digest := sha256.Sum256([]byte(strconv.FormatUint(uid, 10) + "\x00" + identityMaterial))
	identity := hex.EncodeToString(digest[:])
	return processEntry{Identity: identity, Name: name, UID: uint32(uid), Executable: executable}, true
}

func parseListeningPorts(content []byte, family string, limit int) (map[string]portEntry, bool) {
	result := make(map[string]portEntry)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		address, rawPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		portValue, err := strconv.ParseUint(rawPort, 16, 16)
		if err != nil || portValue == 0 {
			continue
		}
		address = strings.ToUpper(address)
		scope := addressScope(address, family)
		key := family + "|" + address + "|" + strconv.FormatUint(portValue, 10)
		result[key] = portEntry{Key: key, Family: family, Port: int(portValue), Scope: scope, Protocol: "tcp"}
		if len(result) >= limit {
			return result, true
		}
	}
	return result, false
}

func addressScope(address, family string) string {
	if strings.Trim(address, "0") == "" {
		return "wildcard"
	}
	if family == "tcp4" && len(address) == 8 && strings.HasSuffix(address, "00007F") {
		return "loopback"
	}
	if family == "tcp6" && (address == "00000000000000000000000001000000" || address == "00000000000000000000000000000001") {
		return "loopback"
	}
	return "specific"
}

func processEvent(process processEntry, now time.Time, generation uint64, key string) domain.Event {
	severity := domain.SeverityLow
	if process.UID == 0 {
		severity = domain.SeverityMedium
	}
	if suspiciousExecutable(process.Executable) {
		severity = domain.SeverityHigh
	}
	evidence := map[string]any{"name": process.Name, "uid": process.UID, "read_only": true}
	if process.Executable != "" {
		evidence["executable"] = process.Executable
	}
	return runtimeEvent("runtime.process.first_seen", severity, "A previously unseen process identity is running", now, generation, key+":"+process.Identity, evidence)
}

func processDriftEvent(process processEntry, previousIdentity string, now time.Time, generation uint64) domain.Event {
	evidence := map[string]any{
		"name": process.Name, "uid": process.UID, "previous_identity": previousIdentity,
		"current_identity": process.Identity, "read_only": true,
	}
	if process.Executable != "" {
		evidence["executable"] = process.Executable
	}
	return runtimeEvent("runtime.process.identity_changed", domain.SeverityHigh, "A process name is now backed by a different executable identity", now, generation, process.Identity+":"+previousIdentity, evidence)
}

func portEvent(port portEntry, opened bool, now time.Time, generation uint64) domain.Event {
	kind := "runtime.port.closed"
	severity := domain.SeverityInfo
	summary := "A TCP listening socket closed"
	change := "closed"
	if opened {
		kind = "runtime.port.opened"
		severity = domain.SeverityMedium
		summary = "A new TCP listening socket opened"
		change = "opened"
		if port.Scope == "wildcard" || port.Scope == "specific" {
			severity = domain.SeverityHigh
		}
	}
	return runtimeEvent(kind, severity, summary, now, generation, port.Key+":"+change, map[string]any{
		"protocol": port.Protocol, "family": port.Family, "port": port.Port, "scope": port.Scope, "change": change, "read_only": true,
	})
}

func runtimeEvent(kind string, severity domain.Severity, summary string, now time.Time, generation uint64, key string, evidence map[string]any) domain.Event {
	digest := sha256.Sum256([]byte(kind + "\x00" + strconv.FormatUint(generation, 10) + "\x00" + key))
	return domain.Event{ID: "evt_run_" + hex.EncodeToString(digest[:12]), Kind: kind, Severity: severity, Summary: summary, OccurredAt: now, Evidence: evidence}
}

func appendBounded(events []domain.Event, limit int, event domain.Event) []domain.Event {
	if len(events) < limit {
		return append(events, event)
	}
	return events
}

func cloneState(value detectorState) detectorState {
	copyValue := detectorState{
		SchemaVersion: value.SchemaVersion,
		Generation:    value.Generation,
		CoverageHash:  value.CoverageHash,
		Known:         make(map[string]processEntry, len(value.Known)),
		Names:         make(map[string]string, len(value.Names)),
		Ports:         make(map[string]portEntry, len(value.Ports)),
	}
	for key, process := range value.Known {
		copyValue.Known[key] = process
	}
	for key, identity := range value.Names {
		copyValue.Names[key] = identity
	}
	for key, port := range value.Ports {
		copyValue.Ports[key] = port
	}
	return copyValue
}

func pruneKnown(known map[string]processEntry, current map[string]processEntry, limit int) {
	if len(known) <= limit {
		return
	}
	type candidate struct {
		identity string
		lastSeen uint64
	}
	candidates := make([]candidate, 0, len(known))
	for identity, process := range known {
		if _, active := current[identity]; !active {
			candidates = append(candidates, candidate{identity, process.LastSeen})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].lastSeen == candidates[j].lastSeen {
			return candidates[i].identity < candidates[j].identity
		}
		return candidates[i].lastSeen < candidates[j].lastSeen
	})
	for _, candidate := range candidates {
		if len(known) <= limit {
			break
		}
		delete(known, candidate.identity)
	}
}

func unionKeys(left, right map[string]portEntry) []string {
	seen := make(map[string]bool, len(left)+len(right))
	keys := make([]string, 0, len(left)+len(right))
	for key := range left {
		seen[key] = true
		keys = append(keys, key)
	}
	for key := range right {
		if !seen[key] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
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
		return detectorState{}, false, errors.New("runtime watch state must be a small regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return detectorState{}, false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxStateBytes+1))
	decoder.DisallowUnknownFields()
	var value detectorState
	if err := decoder.Decode(&value); err != nil {
		return detectorState{}, false, fmt.Errorf("decode runtime watch state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return detectorState{}, false, errors.New("runtime watch state contains trailing JSON")
	}
	if err := validateState(value, detector.config.MaxKnown); err != nil {
		return detectorState{}, false, err
	}
	return value, true, nil
}

func (detector *Detector) saveState(value detectorState) error {
	if err := validateState(value, detector.config.MaxKnown); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > maxStateBytes {
		return errors.New("runtime watch state exceeds size limit")
	}
	directory := filepath.Join(detector.config.StateDir, "detectors")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".runtime-watch-*.tmp")
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

func validateState(value detectorState, maxKnown int) error {
	if value.SchemaVersion != stateSchemaVersion || value.Generation == 0 {
		return errors.New("runtime watch state has an unsupported schema or generation")
	}
	if value.Known == nil || value.Names == nil || value.Ports == nil || len(value.Known) > maxKnown {
		return errors.New("runtime watch state has invalid collections")
	}
	for identity, process := range value.Known {
		if identity != process.Identity || !validSHA256(identity) || !validProcessName(process.Name) || process.LastSeen == 0 || !validExecutable(process.Executable) {
			return errors.New("runtime watch state has an invalid process")
		}
	}
	for _, identity := range value.Names {
		if !validSHA256(identity) || value.Known[identity].Identity == "" {
			return errors.New("runtime watch state has an invalid process name index")
		}
	}
	for key, port := range value.Ports {
		if key != port.Key || port.Protocol != "tcp" || (port.Family != "tcp4" && port.Family != "tcp6") || port.Port < 1 || port.Port > 65535 || (port.Scope != "wildcard" && port.Scope != "loopback" && port.Scope != "specific") {
			return errors.New("runtime watch state has an invalid port")
		}
	}
	return nil
}

func coverageEvidence(issues []issue) map[string]any {
	samples := issues
	if len(samples) > maxIssueSamples {
		samples = samples[:maxIssueSamples]
	}
	return map[string]any{"issue_count": len(issues), "issues": samples, "read_only": true}
}

func suspiciousExecutable(path string) bool {
	clean := strings.TrimSuffix(path, " (deleted)")
	for _, prefix := range []string{"/tmp/", "/var/tmp/", "/dev/shm/"} {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	return strings.HasSuffix(path, " (deleted)")
}

func validExecutable(path string) bool {
	return len(path) <= 512 && !strings.ContainsAny(path, "\x00\r\n")
}

func validProcessName(name string) bool {
	return name != "" && len(name) <= 128 && !strings.ContainsAny(name, "\x00\r\n")
}

func validSHA256(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value)
}

func numeric(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func hashValue(value any) string {
	encoded, _ := json.Marshal(value)
	if string(encoded) == "[]" || string(encoded) == "null" {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func readLimitedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(content)) > limit {
		return nil, errors.New("proc socket table exceeds size limit")
	}
	return content, nil
}
