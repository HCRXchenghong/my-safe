package agent

import (
	"testing"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

func TestPolicyPersistsAndAppliesWithinLocalSafetyCeilings(t *testing.T) {
	t.Parallel()
	policy := domain.Policy{
		ID: "pol_test", AgentID: "agt_test", Revision: 2,
		FileIntegrityEnabled: true, FileWatchPaths: []string{"/srv/app"},
		SSHAuthEnabled: true, SSHThreshold: 7, SSHWindowSeconds: 600,
		RuntimeWatchEnabled: false, UpdatedAt: time.Now().UTC(),
	}
	stateDir := t.TempDir()
	if err := SavePolicy(stateDir, policy); err != nil {
		t.Fatal(err)
	}
	loaded, exists, err := LoadPolicy(stateDir, "agt_test")
	if err != nil || !exists || loaded.Revision != 2 {
		t.Fatalf("LoadPolicy() = %#v, %t, %v", loaded, exists, err)
	}
	config := applyPolicy(Config{}, loaded)
	if len(config.FileWatchPaths) != 1 || config.FileWatchPaths[0] != "/srv/app" || config.SSHThreshold != 7 || config.SSHWindow != 10*time.Minute || !config.DisableRuntimeWatch {
		t.Fatalf("applied config = %#v", config)
	}
	localCeiling := applyPolicy(Config{DisableFileIntegrity: true, DisableSSHAuth: true}, loaded)
	if !localCeiling.DisableFileIntegrity || !localCeiling.DisableSSHAuth {
		t.Fatalf("remote policy bypassed local detector ceiling: %#v", localCeiling)
	}
	if _, _, err := LoadPolicy(stateDir, "agt_other"); err == nil {
		t.Fatal("policy for another Agent was accepted")
	}
}
