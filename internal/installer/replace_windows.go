//go:build windows

package installer

import (
	"errors"
	"os"
)

func replaceFile(source, destination string) error {
	err := os.Rename(source, destination)
	if err == nil {
		return nil
	}
	if removeErr := os.Remove(destination); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}
