package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

const (
	policyFilename = "policy.json"
	maxPolicyBytes = int64(256 << 10)
)

func LoadPolicy(stateDir, agentID string) (domain.Policy, bool, error) {
	path := filepath.Join(stateDir, policyFilename)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return domain.Policy{}, false, nil
	}
	if err != nil {
		return domain.Policy{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxPolicyBytes {
		return domain.Policy{}, false, errors.New("Agent policy file must be a small regular file")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return domain.Policy{}, false, err
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var policy domain.Policy
	if err := decoder.Decode(&policy); err != nil {
		return domain.Policy{}, false, fmt.Errorf("decode Agent policy: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domain.Policy{}, false, errors.New("Agent policy contains trailing JSON")
	}
	if policy.AgentID != agentID {
		return domain.Policy{}, false, errors.New("persisted policy targets a different Agent")
	}
	if err := domain.ValidatePolicy(policy); err != nil {
		return domain.Policy{}, false, err
	}
	return policy, true, nil
}

func SavePolicy(stateDir string, policy domain.Policy) error {
	if err := domain.ValidatePolicy(policy); err != nil {
		return err
	}
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if int64(len(encoded)) > maxPolicyBytes {
		return errors.New("Agent policy exceeds size limit")
	}
	temporary, err := os.CreateTemp(stateDir, ".policy-*.tmp")
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
	if err := os.Rename(temporaryPath, filepath.Join(stateDir, policyFilename)); err != nil {
		return err
	}
	completed = true
	return nil
}
