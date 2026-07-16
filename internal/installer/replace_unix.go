//go:build !windows

package installer

import "os"

func replaceFile(source, destination string) error {
	return os.Rename(source, destination)
}
