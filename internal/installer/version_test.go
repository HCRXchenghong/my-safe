package installer

import "testing"

func TestCompareReleaseVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		left  string
		right string
		want  int
	}{
		{"v1.0.0", "v1.0.0-rc.1", 1},
		{"v1.0.0-rc.2", "v1.0.0-rc.10", -1},
		{"v1.2.0", "v1.10.0", -1},
		{"v2.0.0-alpha", "v2.0.0-alpha", 0},
		{"v2.0.0-alpha.1", "v2.0.0-alpha.beta", -1},
	}
	for _, test := range tests {
		got := compareReleaseVersions(test.left, test.right)
		if got < 0 {
			got = -1
		} else if got > 0 {
			got = 1
		}
		if got != test.want {
			t.Errorf("compareReleaseVersions(%q, %q) = %d, want %d", test.left, test.right, got, test.want)
		}
	}
}
