package localfeed

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/domain"
)

const MaxDatagramBytes = 64 << 10

type Handler func(domain.Event) error

func Listen(ctx context.Context, path string, handler Handler) error {
	if handler == nil {
		return errors.New("local event handler is required")
	}
	path, err := validateSocketPath(path)
	if err != nil {
		return err
	}
	if err := prepareSocketPath(path); err != nil {
		return err
	}
	connection, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return fmt.Errorf("listen on local event socket: %w", err)
	}
	defer func() {
		_ = connection.Close()
		if info, statErr := os.Lstat(path); statErr == nil && info.Mode()&os.ModeSocket != 0 {
			_ = os.Remove(path)
		}
	}()
	if err := os.Chmod(path, 0o660); err != nil {
		return fmt.Errorf("protect local event socket: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = connection.Close()
	}()
	buffer := make([]byte, MaxDatagramBytes+1)
	for {
		count, _, err := connection.ReadFromUnix(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("read local event socket: %w", err)
		}
		if count == 0 || count > MaxDatagramBytes {
			continue
		}
		event, err := Decode(buffer[:count], time.Now().UTC())
		if err != nil {
			continue
		}
		if err := handler(event); err != nil {
			return fmt.Errorf("persist local event: %w", err)
		}
	}
}

func Send(ctx context.Context, path string, event domain.Event) error {
	path, err := validateSocketPath(path)
	if err != nil {
		return err
	}
	if err := Validate(event, time.Now().UTC()); err != nil {
		return err
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("encode local event: %w", err)
	}
	if len(encoded) > MaxDatagramBytes {
		return errors.New("local event exceeds datagram size limit")
	}
	dialer := net.Dialer{Timeout: time.Second}
	connection, err := dialer.DialContext(ctx, "unixgram", path)
	if err != nil {
		return fmt.Errorf("connect local event socket: %w", err)
	}
	defer connection.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = connection.SetWriteDeadline(deadline)
	} else {
		_ = connection.SetWriteDeadline(time.Now().Add(time.Second))
	}
	written, err := connection.Write(encoded)
	if err != nil {
		return fmt.Errorf("write local event socket: %w", err)
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	return nil
}

func Decode(encoded []byte, now time.Time) (domain.Event, error) {
	if len(encoded) == 0 || len(encoded) > MaxDatagramBytes {
		return domain.Event{}, errors.New("local event has invalid size")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var event domain.Event
	if err := decoder.Decode(&event); err != nil {
		return domain.Event{}, fmt.Errorf("decode local event: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return domain.Event{}, errors.New("local event contains trailing JSON")
	}
	if err := Validate(event, now); err != nil {
		return domain.Event{}, err
	}
	return event, nil
}

func Validate(event domain.Event, now time.Time) error {
	if event.AgentID != "" || !event.ReceivedAt.IsZero() {
		return errors.New("local event must not set server-owned fields")
	}
	if !strings.HasPrefix(event.Kind, "gateway.") {
		return errors.New("local event kind must use the gateway namespace")
	}
	if err := domain.ValidateEvent(event, now); err != nil {
		return fmt.Errorf("validate local event: %w", err)
	}
	return nil
}

func validateSocketPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\x00\r\n") {
		return "", errors.New("local event socket path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve local event socket path: %w", err)
	}
	absolute = filepath.Clean(absolute)
	if len(absolute) > 100 {
		return "", errors.New("local event socket path is too long")
	}
	return absolute, nil
}

func prepareSocketPath(path string) error {
	directory := filepath.Dir(path)
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("stat local event directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("local event directory must be a real directory")
	}
	info, err = os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat local event socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("refusing to replace a non-socket local event path")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale local event socket: %w", err)
	}
	return nil
}
