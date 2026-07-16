package domain

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
)

const maxEvidenceBytes = 64 << 10

func ValidateRegistration(machineID, hostname, version, platform, architecture string) error {
	fields := []struct {
		name  string
		value string
		max   int
	}{
		{"machine_id", machineID, 128},
		{"hostname", hostname, 255},
		{"version", version, 64},
		{"platform", platform, 32},
		{"architecture", architecture, 32},
	}
	for _, field := range fields {
		if strings.TrimSpace(field.value) == "" {
			return fmt.Errorf("%s is required", field.name)
		}
		if len(field.value) > field.max {
			return fmt.Errorf("%s exceeds %d bytes", field.name, field.max)
		}
		if strings.ContainsAny(field.value, "\r\n\x00") {
			return fmt.Errorf("%s contains control characters", field.name)
		}
	}
	return nil
}

func ValidatePolicy(policy Policy) error {
	if strings.TrimSpace(policy.ID) == "" || len(policy.ID) > 64 || strings.TrimSpace(policy.AgentID) == "" || len(policy.AgentID) > 64 || policy.Revision < 1 || policy.UpdatedAt.IsZero() {
		return errors.New("policy identity, revision, and update time are required")
	}
	if len(policy.FileWatchPaths) > 64 {
		return errors.New("policy has too many file watch paths")
	}
	seen := make(map[string]bool, len(policy.FileWatchPaths))
	for _, item := range policy.FileWatchPaths {
		if len(item) == 0 || len(item) > 512 || !strings.HasPrefix(item, "/") || path.Clean(item) != item || strings.ContainsAny(item, "\x00\r\n") || seen[item] {
			return errors.New("policy contains an invalid or duplicate file watch path")
		}
		seen[item] = true
	}
	if policy.SSHThreshold < 2 || policy.SSHThreshold > 100 || policy.SSHWindowSeconds < 10 || policy.SSHWindowSeconds > 86400 {
		return errors.New("policy SSH threshold or window is outside the safe range")
	}
	return nil
}

func ValidateEvent(event Event, now time.Time) error {
	if strings.TrimSpace(event.ID) == "" || len(event.ID) > 128 {
		return errors.New("event id is required and must not exceed 128 bytes")
	}
	if strings.TrimSpace(event.Kind) == "" || len(event.Kind) > 128 {
		return errors.New("event kind is required and must not exceed 128 bytes")
	}
	if !event.Severity.Valid() {
		return errors.New("event severity is invalid")
	}
	if strings.TrimSpace(event.Summary) == "" || len(event.Summary) > 2048 {
		return errors.New("event summary is required and must not exceed 2048 bytes")
	}
	if event.OccurredAt.IsZero() {
		return errors.New("occurred_at is required")
	}
	if event.OccurredAt.After(now.Add(5 * time.Minute)) {
		return errors.New("occurred_at is too far in the future")
	}
	encoded, err := json.Marshal(event.Evidence)
	if err != nil {
		return fmt.Errorf("encode evidence: %w", err)
	}
	if len(encoded) > maxEvidenceBytes {
		return fmt.Errorf("evidence exceeds %d bytes", maxEvidenceBytes)
	}
	return nil
}
