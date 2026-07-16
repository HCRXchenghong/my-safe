//go:build linux

package installer

import "os"

func hasRootPrivileges() bool {
	return os.Geteuid() == 0
}
