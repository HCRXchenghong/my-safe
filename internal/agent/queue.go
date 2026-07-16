package agent

import (
	"crypto/aes"
	"crypto/cipher"
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
)

const (
	queueKeyFilename = "queue.key"
	queueDirectory   = "queue"
	queueFileSuffix  = ".event"
	maxQueueFileSize = int64(1 << 20)
	maxQueueEntries  = 10_000
)

type EncryptedQueue struct {
	mu   sync.Mutex
	dir  string
	aead cipher.AEAD
}

type QueueBatch struct {
	Events []domain.Event
	files  []string
}

func OpenEncryptedQueue(stateDir string) (*EncryptedQueue, error) {
	if err := ensurePrivateDirectory(stateDir); err != nil {
		return nil, err
	}
	key, err := loadOrCreateQueueKey(filepath.Join(stateDir, queueKeyFilename))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create queue cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create queue AEAD: %w", err)
	}
	directory := filepath.Join(stateDir, queueDirectory)
	if err := ensurePrivateDirectory(directory); err != nil {
		return nil, err
	}
	return &EncryptedQueue{dir: directory, aead: aead}, nil
}

func (queue *EncryptedQueue) Enqueue(event domain.Event) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	files, err := queueFiles(queue.dir)
	if err != nil {
		return err
	}
	if len(files) >= maxQueueEntries {
		return fmt.Errorf("encrypted queue reached its %d event safety limit", maxQueueEntries)
	}
	plaintext, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode queued event: %w", err)
	}
	nonce := make([]byte, queue.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("generate queue nonce: %w", err)
	}
	sealed := queue.aead.Seal(nil, nonce, plaintext, nil)
	payload := append(nonce, sealed...)
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return fmt.Errorf("generate queue filename: %w", err)
	}
	filename := fmt.Sprintf("%020d-%s%s", time.Now().UTC().UnixNano(), hex.EncodeToString(suffix), queueFileSuffix)
	path := filepath.Join(queue.dir, filename)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create queued event: %w", err)
	}
	completed := false
	defer func() {
		_ = file.Close()
		if !completed {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(payload); err != nil {
		return fmt.Errorf("write queued event: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync queued event: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close queued event: %w", err)
	}
	completed = true
	return nil
}

func (queue *EncryptedQueue) Peek(limit int) (QueueBatch, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if limit <= 0 || limit > 100 {
		return QueueBatch{}, errors.New("queue batch limit must be between 1 and 100")
	}
	files, err := queueFiles(queue.dir)
	if err != nil {
		return QueueBatch{}, err
	}
	if len(files) > limit {
		files = files[:limit]
	}
	batch := QueueBatch{
		Events: make([]domain.Event, 0, len(files)),
		files:  make([]string, 0, len(files)),
	}
	for _, filename := range files {
		path := filepath.Join(queue.dir, filename)
		info, err := os.Stat(path)
		if err != nil {
			return QueueBatch{}, fmt.Errorf("stat queued event: %w", err)
		}
		if info.Size() <= int64(queue.aead.NonceSize()) || info.Size() > maxQueueFileSize {
			return QueueBatch{}, fmt.Errorf("queued event %q has invalid size", filename)
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			return QueueBatch{}, fmt.Errorf("read queued event: %w", err)
		}
		nonce, ciphertext := payload[:queue.aead.NonceSize()], payload[queue.aead.NonceSize():]
		plaintext, err := queue.aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return QueueBatch{}, fmt.Errorf("authenticate queued event %q: %w", filename, err)
		}
		var event domain.Event
		if err := json.Unmarshal(plaintext, &event); err != nil {
			return QueueBatch{}, fmt.Errorf("decode queued event %q: %w", filename, err)
		}
		batch.Events = append(batch.Events, event)
		batch.files = append(batch.files, filename)
	}
	return batch, nil
}

func (queue *EncryptedQueue) Ack(batch QueueBatch) error {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	if len(batch.Events) != len(batch.files) {
		return errors.New("queue batch is invalid")
	}
	for _, filename := range batch.files {
		if filepath.Base(filename) != filename || !strings.HasSuffix(filename, queueFileSuffix) {
			return errors.New("queue batch contains an invalid filename")
		}
		if err := os.Remove(filepath.Join(queue.dir, filename)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("acknowledge queued event: %w", err)
		}
	}
	return nil
}

func (queue *EncryptedQueue) Len() (int, error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	files, err := queueFiles(queue.dir)
	return len(files), err
}

func queueFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read queue directory: %w", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), queueFileSuffix) {
			files = append(files, entry.Name())
		}
	}
	sort.Strings(files)
	return files, nil
}

func loadOrCreateQueueKey(path string) ([]byte, error) {
	key, err := os.ReadFile(path)
	if err == nil {
		if len(key) != 32 {
			return nil, errors.New("queue key has invalid length")
		}
		return key, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read queue key: %w", err)
	}
	key = make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate queue key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return loadOrCreateQueueKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("create queue key: %w", err)
	}
	if _, err := file.Write(key); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("write queue key: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("sync queue key: %w", err)
	}
	if err := file.Close(); err != nil {
		return nil, fmt.Errorf("close queue key: %w", err)
	}
	return key, nil
}
