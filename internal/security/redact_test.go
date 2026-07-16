package security

import (
	"reflect"
	"testing"
)

func TestRedactMapRecursivelyCopiesAndRedacts(t *testing.T) {
	input := map[string]any{
		"path":          "/login",
		"Authorization": "Bearer do-not-store",
		"nested": map[string]any{
			"password_hash": "still-sensitive",
			"status":        401,
		},
		"items": []any{map[string]any{"session-token": "secret", "safe": true}},
	}

	got := RedactMap(input)
	want := map[string]any{
		"path":          "/login",
		"Authorization": Redacted,
		"nested": map[string]any{
			"password_hash": Redacted,
			"status":        401,
		},
		"items": []any{map[string]any{"session-token": Redacted, "safe": true}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("RedactMap() = %#v, want %#v", got, want)
	}
	if input["Authorization"] == Redacted {
		t.Fatal("RedactMap mutated its input")
	}
}
