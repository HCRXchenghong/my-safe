package gatewayevents

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
	"github.com/HCRXchenghong/my-safe/internal/localfeed"
)

const (
	defaultMaxEvents = 10_000
	fileSuffix       = ".gateway-event"
	maxFileBytes     = int64(localfeed.MaxDatagramBytes)
)

type Sender func(context.Context, string, domain.Event) error

type Config struct {
	StateDir   string
	SocketPath string
	MaxEvents  int
	Now        func() time.Time
	Send       Sender
}

type Outbox struct {
	mu         sync.Mutex
	directory  string
	socketPath string
	maxEvents  int
	now        func() time.Time
	send       Sender
}

func New(config Config) (*Outbox, error) {
	if strings.TrimSpace(config.StateDir) == "" || strings.TrimSpace(config.SocketPath) == "" {
		return nil, errors.New("Gateway event state directory and socket path are required")
	}
	stateDir, err := filepath.Abs(config.StateDir)
	if err != nil {
		return nil, err
	}
	if config.MaxEvents == 0 {
		config.MaxEvents = defaultMaxEvents
	}
	if config.MaxEvents < 1 || config.MaxEvents > 100_000 {
		return nil, errors.New("Gateway event outbox limit must be between 1 and 100000")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Send == nil {
		config.Send = localfeed.Send
	}
	directory := filepath.Join(stateDir, "outbox")
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	return &Outbox{directory: directory, socketPath: config.SocketPath, maxEvents: config.MaxEvents, now: config.Now, send: config.Send}, nil
}

func (outbox *Outbox) Emit(event domain.Event) error {
	if err := localfeed.Validate(event, outbox.now().UTC()); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err := outbox.send(ctx, outbox.socketPath, event)
	cancel()
	if err == nil {
		return nil
	}
	return outbox.persist(event)
}

func (outbox *Outbox) Run(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := outbox.Flush(ctx, 100); err != nil && ctx.Err() == nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (outbox *Outbox) Flush(ctx context.Context, limit int) (int, error) {
	if limit < 1 || limit > 1000 {
		return 0, errors.New("Gateway event flush limit must be between 1 and 1000")
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	files, err := outboxFiles(outbox.directory)
	if err != nil {
		return 0, err
	}
	if len(files) > limit {
		files = files[:limit]
	}
	flushed := 0
	for _, name := range files {
		if err := ctx.Err(); err != nil {
			return flushed, err
		}
		path := filepath.Join(outbox.directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			return flushed, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > maxFileBytes {
			return flushed, fmt.Errorf("unsafe Gateway outbox file %q", name)
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return flushed, err
		}
		event, err := localfeed.Decode(encoded, outbox.now().UTC())
		if err != nil {
			return flushed, fmt.Errorf("decode Gateway outbox event: %w", err)
		}
		sendContext, cancel := context.WithTimeout(ctx, time.Second)
		err = outbox.send(sendContext, outbox.socketPath, event)
		cancel()
		if err != nil {
			return flushed, nil
		}
		if err := os.Remove(path); err != nil {
			return flushed, err
		}
		flushed++
	}
	return flushed, nil
}

func (outbox *Outbox) persist(event domain.Event) error {
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > localfeed.MaxDatagramBytes {
		return errors.New("Gateway event exceeds outbox size limit")
	}
	outbox.mu.Lock()
	defer outbox.mu.Unlock()
	files, err := outboxFiles(outbox.directory)
	if err != nil {
		return err
	}
	if len(files) >= outbox.maxEvents {
		return fmt.Errorf("Gateway event outbox reached its %d event limit", outbox.maxEvents)
	}
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%s%s", outbox.now().UTC().UnixNano(), hex.EncodeToString(random), fileSuffix)
	path := filepath.Join(outbox.directory, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		_ = file.Close()
		if !completed {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	completed = true
	return nil
}

func ensurePrivateDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Gateway event outbox must be a real directory")
	}
	return os.Chmod(path, 0o700)
}

func outboxFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), fileSuffix) {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}
