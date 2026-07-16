//go:build !linux

package scanner

import "context"

func platformEvidence(_ context.Context) map[string]any {
	return map[string]any{
		"scan_scope": "limited_non_linux_development_host",
	}
}
