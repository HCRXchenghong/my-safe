//go:build linux

package scanner

import (
	"context"
	"os"
	"strings"
)

func platformEvidence(_ context.Context) map[string]any {
	evidence := make(map[string]any)
	if content, err := os.ReadFile("/etc/os-release"); err == nil {
		evidence["os_release"] = parseOSRelease(content)
	} else {
		evidence["os_release_available"] = false
	}
	if content, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		evidence["kernel_release"] = strings.TrimSpace(string(content))
	}

	ports := make(map[int]struct{})
	for _, path := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		if content, err := os.ReadFile(path); err == nil {
			for _, port := range parseListeningPorts(content) {
				ports[port] = struct{}{}
			}
		}
	}
	if len(ports) > 0 {
		merged := make([]int, 0, len(ports))
		for port := range ports {
			merged = append(merged, port)
		}
		// parseListeningPorts already sorts each input, but merged map order is not stable.
		sortInts(merged)
		evidence["listening_tcp_ports"] = merged
	}

	configFiles := make(map[string]any)
	for _, path := range []string{"/etc/nginx/nginx.conf", "/etc/ssh/sshd_config"} {
		if info, err := os.Stat(path); err == nil {
			configFiles[path] = map[string]any{
				"exists": true,
				"mode":   info.Mode().Perm().String(),
			}
		} else if os.IsNotExist(err) {
			configFiles[path] = map[string]any{"exists": false}
		} else {
			configFiles[path] = map[string]any{"exists": true, "readable": false}
		}
	}
	evidence["config_files"] = configFiles
	return evidence
}

func sortInts(values []int) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j] < values[j-1]; j-- {
			values[j], values[j-1] = values[j-1], values[j]
		}
	}
}
