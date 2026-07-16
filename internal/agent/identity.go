package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/HCRXchenghong/my-safe/internal/id"
)

const (
	machineIDFilename  = "machine.id"
	credentialFilename = "credentials.json"
)

type Identity struct {
	MachineID  string `json:"machine_id"`
	AgentID    string `json:"agent_id,omitempty"`
	Credential string `json:"credential,omitempty"`
}

func (identity Identity) Registered() bool {
	return identity.AgentID != "" && identity.Credential != ""
}

func LoadIdentity(stateDir string) (Identity, error) {
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return Identity{}, err
	}
	machineID, err := loadOrCreateMachineID(filepath.Join(stateDir, machineIDFilename))
	if err != nil {
		return Identity{}, err
	}
	identity := Identity{MachineID: machineID}
	encoded, err := os.ReadFile(filepath.Join(stateDir, credentialFilename))
	if errors.Is(err, os.ErrNotExist) {
		return identity, nil
	}
	if err != nil {
		return Identity{}, fmt.Errorf("read credentials: %w", err)
	}
	if err := json.Unmarshal(encoded, &identity); err != nil {
		return Identity{}, fmt.Errorf("decode credentials: %w", err)
	}
	if identity.MachineID != machineID || !identity.Registered() {
		return Identity{}, errors.New("credentials do not match the local machine identity")
	}
	return identity, nil
}

func SaveCredentials(stateDir string, identity Identity) error {
	if strings.TrimSpace(identity.MachineID) == "" || !identity.Registered() {
		return errors.New("complete identity is required")
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return fmt.Errorf("encode credentials: %w", err)
	}
	path := filepath.Join(stateDir, credentialFilename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create credentials: %w", err)
	}
	completed := false
	defer func() {
		_ = file.Close()
		if !completed {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync credentials: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close credentials: %w", err)
	}
	completed = true
	return nil
}

func loadOrCreateMachineID(path string) (string, error) {
	encoded, err := os.ReadFile(path)
	if err == nil {
		machineID := strings.TrimSpace(string(encoded))
		if machineID == "" || len(machineID) > 128 {
			return "", errors.New("local machine id is invalid")
		}
		return machineID, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read machine id: %w", err)
	}
	machineID, err := id.Random("mch_", 18)
	if err != nil {
		return "", fmt.Errorf("generate machine id: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateMachineID(path)
	}
	if err != nil {
		return "", fmt.Errorf("create machine id: %w", err)
	}
	if _, err := file.WriteString(machineID + "\n"); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("write machine id: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return "", fmt.Errorf("sync machine id: %w", err)
	}
	if err := file.Close(); err != nil {
		return "", fmt.Errorf("close machine id: %w", err)
	}
	return machineID, nil
}

func ensurePrivateDirectory(path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("state directory is required")
	}
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		return fmt.Errorf("set state directory permissions: %w", err)
	}
	return nil
}
