package security

import "strings"

const Redacted = "[REDACTED]"

var sensitiveKeyFragments = []string{
	"authorization",
	"cookie",
	"password",
	"passwd",
	"private_key",
	"secret",
	"token",
}

// RedactMap recursively copies a map while replacing values whose key names
// indicate credentials or request secrets. The input map is not modified.
func RedactMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	output := make(map[string]any, len(input))
	for key, value := range input {
		if sensitiveKey(key) {
			output[key] = Redacted
			continue
		}
		output[key] = redactValue(value)
	}
	return output
}

func redactValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return RedactMap(typed)
	case []any:
		copy := make([]any, len(typed))
		for i := range typed {
			copy[i] = redactValue(typed[i])
		}
		return copy
	default:
		return value
	}
}

func sensitiveKey(key string) bool {
	normalized := strings.ToLower(strings.TrimSpace(key))
	normalized = strings.ReplaceAll(normalized, "-", "_")
	for _, fragment := range sensitiveKeyFragments {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return false
}
