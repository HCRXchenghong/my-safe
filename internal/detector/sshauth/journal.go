package sshauth

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"time"
)

// SystemdJournal reads only sshd records through fixed journalctl arguments.
// It never invokes a shell and never includes a raw record in an event.
type SystemdJournal struct{}

func (SystemdJournal) Baseline(ctx context.Context) (string, error) {
	records, _, err := runJournalctl(ctx, []string{
		"--quiet", "--no-pager", "--output=json", "--reverse", "--lines=1", "_COMM=sshd",
	}, 2)
	if err != nil {
		return "", err
	}
	if len(records) == 0 {
		return "", nil
	}
	return records[0].Cursor, nil
}

func (SystemdJournal) ReadAfter(ctx context.Context, cursor string, since time.Time, limit int) ([]JournalRecord, bool, error) {
	if limit < 1 {
		return nil, false, errors.New("journal record limit must be positive")
	}
	arguments := []string{"--quiet", "--no-pager", "--output=json"}
	if cursor != "" {
		if !validJournalCursor(cursor) {
			return nil, false, errors.New("journal cursor is invalid")
		}
		arguments = append(arguments, "--after-cursor="+cursor)
	} else {
		seconds := since.Unix()
		micros := since.Nanosecond() / 1000
		arguments = append(arguments, "--since=@"+strconv.FormatInt(seconds, 10)+"."+fmt.Sprintf("%06d", micros))
	}
	arguments = append(arguments, "_COMM=sshd")
	records, stopped, err := runJournalctl(ctx, arguments, limit+1)
	if err != nil {
		return nil, false, err
	}
	limited := stopped || len(records) > limit
	if len(records) > limit {
		records = records[:limit]
	}
	return records, limited, nil
}

func runJournalctl(ctx context.Context, arguments []string, maxRecords int) ([]JournalRecord, bool, error) {
	command := exec.CommandContext(ctx, "journalctl", arguments...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, false, errors.New("open journalctl output")
	}
	command.Stderr = io.Discard
	if err := command.Start(); err != nil {
		return nil, false, errors.New("start journalctl")
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64<<10), 256<<10)
	records := make([]JournalRecord, 0, maxRecords)
	stopped := false
	for scanner.Scan() {
		var raw struct {
			Cursor  json.RawMessage `json:"__CURSOR"`
			Message json.RawMessage `json:"MESSAGE"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			continue
		}
		var record JournalRecord
		if json.Unmarshal(raw.Cursor, &record.Cursor) != nil || json.Unmarshal(raw.Message, &record.Message) != nil || !validJournalCursor(record.Cursor) {
			continue
		}
		records = append(records, record)
		if len(records) >= maxRecords {
			stopped = true
			_ = command.Process.Kill()
			break
		}
	}
	scanErr := scanner.Err()
	waitErr := command.Wait()
	if err := ctx.Err(); err != nil {
		return nil, stopped, err
	}
	if scanErr != nil {
		return nil, stopped, errors.New("read journalctl output")
	}
	if waitErr != nil && !stopped {
		return nil, false, errors.New("journalctl query failed")
	}
	return records, stopped, nil
}
