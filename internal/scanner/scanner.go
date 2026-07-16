package scanner

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/id"
)

type Scanner struct {
	Now func() time.Time
}

func (scanner Scanner) Scan(ctx context.Context) (domain.Event, error) {
	now := time.Now
	if scanner.Now != nil {
		now = scanner.Now
	}
	eventID, err := id.Random("evt_", 18)
	if err != nil {
		return domain.Event{}, fmt.Errorf("generate scan event id: %w", err)
	}
	evidence := map[string]any{
		"platform":     runtime.GOOS,
		"architecture": runtime.GOARCH,
		"read_only":    true,
	}
	for key, value := range platformEvidence(ctx) {
		evidence[key] = value
	}
	return domain.Event{
		ID:         eventID,
		Kind:       "host.inventory",
		Severity:   domain.SeverityInfo,
		Summary:    "Read-only host inventory scan completed",
		OccurredAt: now().UTC(),
		Evidence:   evidence,
	}, nil
}

func parseOSRelease(content []byte) map[string]string {
	allowed := map[string]bool{"ID": true, "NAME": true, "VERSION_ID": true, "VERSION_CODENAME": true}
	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || !allowed[key] {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "\"")
		if len(value) <= 128 {
			result[key] = value
		}
	}
	return result
}

func parseListeningPorts(content []byte) []int {
	ports := make(map[int]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		_, rawPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(rawPort, 16, 16)
		if err == nil && port > 0 {
			ports[int(port)] = struct{}{}
		}
	}
	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}
