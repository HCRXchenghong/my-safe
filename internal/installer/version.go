package installer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const installedReleasePath = "/var/lib/my-safe/installed-release.json"

var releaseVersionPattern = regexp.MustCompile(`^v?([0-9]+)\.([0-9]+)\.([0-9]+)(?:-([0-9A-Za-z.-]+))?$`)

type installedRelease struct {
	Version       string    `json:"version"`
	InstalledAt   time.Time `json:"installed_at"`
	TransactionID string    `json:"transaction_id"`
}

func loadInstalledRelease(root string) (installedRelease, bool, error) {
	path := rootPath(root, installedReleasePath)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return installedRelease{}, false, nil
	}
	if err != nil {
		return installedRelease{}, false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 4096 {
		return installedRelease{}, false, errors.New("installed release state must be a small regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return installedRelease{}, false, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 4097))
	decoder.DisallowUnknownFields()
	var state installedRelease
	if err := decoder.Decode(&state); err != nil {
		return installedRelease{}, false, fmt.Errorf("decode installed release state: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return installedRelease{}, false, errors.New("installed release state contains trailing JSON")
	}
	if !releaseVersionPattern.MatchString(state.Version) || state.InstalledAt.IsZero() || strings.TrimSpace(state.TransactionID) == "" || filepath.Base(state.TransactionID) != state.TransactionID {
		return installedRelease{}, false, errors.New("installed release state is invalid")
	}
	return state, true, nil
}

func compareReleaseVersions(left, right string) int {
	leftMatch := releaseVersionPattern.FindStringSubmatch(left)
	rightMatch := releaseVersionPattern.FindStringSubmatch(right)
	if len(leftMatch) != 5 || len(rightMatch) != 5 {
		return strings.Compare(left, right)
	}
	for index := 1; index <= 3; index++ {
		leftNumber, _ := strconv.ParseUint(leftMatch[index], 10, 64)
		rightNumber, _ := strconv.ParseUint(rightMatch[index], 10, 64)
		if leftNumber < rightNumber {
			return -1
		}
		if leftNumber > rightNumber {
			return 1
		}
	}
	return comparePrerelease(leftMatch[4], rightMatch[4])
}

func comparePrerelease(left, right string) int {
	if left == right {
		return 0
	}
	if left == "" {
		return 1
	}
	if right == "" {
		return -1
	}
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	for index := 0; index < len(leftParts) && index < len(rightParts); index++ {
		if leftParts[index] == rightParts[index] {
			continue
		}
		leftNumber, leftErr := strconv.ParseUint(leftParts[index], 10, 64)
		rightNumber, rightErr := strconv.ParseUint(rightParts[index], 10, 64)
		switch {
		case leftErr == nil && rightErr == nil:
			if leftNumber < rightNumber {
				return -1
			}
			return 1
		case leftErr == nil:
			return -1
		case rightErr == nil:
			return 1
		default:
			return strings.Compare(leftParts[index], rightParts[index])
		}
	}
	if len(leftParts) < len(rightParts) {
		return -1
	}
	return 1
}
