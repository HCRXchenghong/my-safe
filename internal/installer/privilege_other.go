//go:build !linux

package installer

func hasRootPrivileges() bool {
	return false
}
