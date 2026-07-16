package releasebundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const SchemaVersion = 2

var (
	versionPattern  = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$`)
	artifactPattern = regexp.MustCompile(`^mysafe-(agent|control|gateway|installer)-linux-(amd64|arm64)(\.deb)?$`)
)

type Artifact struct {
	Name      string `json:"name"`
	Component string `json:"component"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	SHA256    string `json:"sha256"`
	Size      int64  `json:"size"`
	Mode      uint32 `json:"mode"`
	Format    string `json:"format"`
}

type Manifest struct {
	SchemaVersion int        `json:"schema_version"`
	Version       string     `json:"version"`
	CreatedAt     time.Time  `json:"created_at"`
	Artifacts     []Artifact `json:"artifacts"`
}

func Build(directory, version string, createdAt time.Time) (Manifest, error) {
	if !versionPattern.MatchString(version) {
		return Manifest{}, errors.New("version must be SemVer, for example v0.1.0")
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return Manifest{}, fmt.Errorf("read release directory: %w", err)
	}
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Version:       version,
		CreatedAt:     createdAt.UTC().Truncate(time.Second),
		Artifacts:     make([]Artifact, 0),
	}
	for _, entry := range entries {
		match := artifactPattern.FindStringSubmatch(entry.Name())
		if len(match) != 4 {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return Manifest{}, fmt.Errorf("artifact %q must be a regular file, not a link", entry.Name())
		}
		path := filepath.Join(directory, entry.Name())
		digest, size, err := hashFile(path)
		if err != nil {
			return Manifest{}, err
		}
		format := "binary"
		mode := uint32(0o755)
		if match[3] == ".deb" {
			format = "deb"
			mode = 0o644
		}
		manifest.Artifacts = append(manifest.Artifacts, Artifact{
			Name:      entry.Name(),
			Component: match[1],
			OS:        "linux",
			Arch:      match[2],
			SHA256:    digest,
			Size:      size,
			// Cross-builds made on Windows cannot preserve Unix mode bits in the
			// source directory, so release modes are format-defined.
			Mode:   mode,
			Format: format,
		})
	}
	sort.Slice(manifest.Artifacts, func(i, j int) bool {
		return manifest.Artifacts[i].Name < manifest.Artifacts[j].Name
	})
	if err := Validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Encode(manifest Manifest) ([]byte, error) {
	if err := Validate(manifest); err != nil {
		return nil, err
	}
	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode release manifest: %w", err)
	}
	return append(encoded, '\n'), nil
}

func Decode(encoded []byte) (Manifest, error) {
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	var manifest Manifest
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Manifest{}, errors.New("release manifest contains trailing JSON")
	}
	if err := Validate(manifest); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func Validate(manifest Manifest) error {
	if manifest.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported manifest schema version %d", manifest.SchemaVersion)
	}
	if !versionPattern.MatchString(manifest.Version) {
		return errors.New("manifest version is not valid SemVer")
	}
	if manifest.CreatedAt.IsZero() {
		return errors.New("manifest created_at is required")
	}
	if len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > 32 {
		return errors.New("manifest must contain between 1 and 32 artifacts")
	}
	seen := make(map[string]bool, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		match := artifactPattern.FindStringSubmatch(artifact.Name)
		if len(match) != 4 || filepath.Base(artifact.Name) != artifact.Name {
			return fmt.Errorf("unsafe or unsupported artifact name %q", artifact.Name)
		}
		if seen[artifact.Name] {
			return fmt.Errorf("duplicate artifact %q", artifact.Name)
		}
		seen[artifact.Name] = true
		expectedFormat := "binary"
		expectedMode := uint32(0o755)
		if match[3] == ".deb" {
			expectedFormat = "deb"
			expectedMode = 0o644
		}
		if artifact.Component != match[1] || artifact.OS != "linux" || artifact.Arch != match[2] || artifact.Format != expectedFormat {
			return fmt.Errorf("artifact identity does not match filename %q", artifact.Name)
		}
		if artifact.Size <= 0 || artifact.Size > 256<<20 {
			return fmt.Errorf("artifact %q has invalid size", artifact.Name)
		}
		if artifact.Mode != expectedMode {
			return fmt.Errorf("artifact %q has an invalid release mode", artifact.Name)
		}
		digest, err := hex.DecodeString(artifact.SHA256)
		if err != nil || len(digest) != sha256.Size || artifact.SHA256 != strings.ToLower(artifact.SHA256) {
			return fmt.Errorf("artifact %q has invalid SHA-256", artifact.Name)
		}
	}
	return nil
}

func VerifyArtifacts(directory string, manifest Manifest) error {
	if err := Validate(manifest); err != nil {
		return err
	}
	listed := make(map[string]bool, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		listed[artifact.Name] = true
		if err := verifyArtifact(directory, artifact); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read release directory: %w", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "mysafe-") && artifactPattern.MatchString(entry.Name()) && !listed[entry.Name()] {
			return fmt.Errorf("unlisted My Safe artifact %q", entry.Name())
		}
	}
	return nil
}

func VerifySelection(directory string, manifest Manifest, operatingSystem, architecture string, components ...string) error {
	if err := Validate(manifest); err != nil {
		return err
	}
	if len(components) == 0 {
		return errors.New("at least one release component must be selected")
	}
	seen := make(map[string]bool, len(components))
	for _, component := range components {
		if seen[component] {
			continue
		}
		seen[component] = true
		artifact, err := Select(manifest, component, operatingSystem, architecture)
		if err != nil {
			return err
		}
		if err := verifyArtifact(directory, artifact); err != nil {
			return err
		}
	}
	return nil
}

func verifyArtifact(directory string, artifact Artifact) error {
	path := filepath.Join(directory, artifact.Name)
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat artifact %q: %w", artifact.Name, err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("artifact %q is not a regular file", artifact.Name)
	}
	digest, size, err := hashFile(path)
	if err != nil {
		return err
	}
	if size != artifact.Size {
		return fmt.Errorf("artifact %q size mismatch", artifact.Name)
	}
	if digest != artifact.SHA256 {
		return fmt.Errorf("artifact %q SHA-256 mismatch", artifact.Name)
	}
	return nil
}

func Select(manifest Manifest, component, operatingSystem, architecture string) (Artifact, error) {
	return SelectFormat(manifest, component, operatingSystem, architecture, "binary")
}

func SelectFormat(manifest Manifest, component, operatingSystem, architecture, format string) (Artifact, error) {
	for _, artifact := range manifest.Artifacts {
		if artifact.Component == component && artifact.OS == operatingSystem && artifact.Arch == architecture && artifact.Format == format {
			return artifact, nil
		}
	}
	return Artifact{}, fmt.Errorf("release %s has no %s %s artifact for %s/%s", manifest.Version, format, component, operatingSystem, architecture)
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, fmt.Errorf("open artifact %q: %w", filepath.Base(path), err)
	}
	defer file.Close()
	hash := sha256.New()
	size, err := io.Copy(hash, io.LimitReader(file, (256<<20)+1))
	if err != nil {
		return "", 0, fmt.Errorf("hash artifact %q: %w", filepath.Base(path), err)
	}
	if size > 256<<20 {
		return "", 0, fmt.Errorf("artifact %q exceeds 256 MiB", filepath.Base(path))
	}
	return hex.EncodeToString(hash.Sum(nil)), size, nil
}
