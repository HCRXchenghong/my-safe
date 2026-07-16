package id

import (
	"crypto/rand"
	"encoding/base64"
)

// Random returns a URL-safe, cryptographically random identifier.
func Random(prefix string, size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buffer), nil
}
