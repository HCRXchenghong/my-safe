package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/HCRXchenghong/my-safe/internal/releasebundle"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mysafe-release:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: mysafe-release keygen|manifest|verify [options]")
	}
	switch arguments[0] {
	case "keygen":
		return keygen(arguments[1:])
	case "manifest":
		return manifest(arguments[1:])
	case "verify":
		return verify(arguments[1:])
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func keygen(arguments []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	privatePath := flags.String("private-key", "", "new private key path")
	publicPath := flags.String("public-key", "", "new public key path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *privatePath == "" || *publicPath == "" {
		return errors.New("-private-key and -public-key are required")
	}
	if err := os.MkdirAll(filepath.Dir(*privatePath), 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(*publicPath), 0o755); err != nil {
		return err
	}
	fingerprint, err := releasebundle.GenerateKeyFiles(*privatePath, *publicPath)
	if err != nil {
		return err
	}
	fmt.Println("release public key fingerprint:", fingerprint)
	return nil
}

func manifest(arguments []string) error {
	flags := flag.NewFlagSet("manifest", flag.ContinueOnError)
	directory := flags.String("bundle", "dist", "release artifact directory")
	version := flags.String("version", "", "release SemVer")
	privatePath := flags.String("private-key", "", "Ed25519 private key path")
	manifestPath := flags.String("output", "release-manifest.json", "manifest output path")
	signaturePath := flags.String("signature", "release-manifest.sig", "signature output path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *version == "" || *privatePath == "" {
		return errors.New("-version and -private-key are required")
	}
	value, err := releasebundle.Build(*directory, *version, time.Now())
	if err != nil {
		return err
	}
	encoded, err := releasebundle.Encode(value)
	if err != nil {
		return err
	}
	privateKey, err := releasebundle.LoadPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	if err := writeNew(*manifestPath, encoded, 0o644); err != nil {
		return err
	}
	if err := writeNew(*signaturePath, []byte(releasebundle.Sign(encoded, privateKey)), 0o644); err != nil {
		_ = os.Remove(*manifestPath)
		return err
	}
	fmt.Printf("signed %d artifacts for %s\n", len(value.Artifacts), value.Version)
	return nil
}

func verify(arguments []string) error {
	flags := flag.NewFlagSet("verify", flag.ContinueOnError)
	directory := flags.String("bundle", "dist", "release artifact directory")
	manifestPath := flags.String("manifest", "release-manifest.json", "manifest path")
	signaturePath := flags.String("signature", "release-manifest.sig", "signature path")
	publicPath := flags.String("public-key", "", "Ed25519 public key path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *publicPath == "" {
		return errors.New("-public-key is required")
	}
	encoded, err := os.ReadFile(*manifestPath)
	if err != nil {
		return err
	}
	signature, err := os.ReadFile(*signaturePath)
	if err != nil {
		return err
	}
	publicKey, err := releasebundle.LoadPublicKey(*publicPath)
	if err != nil {
		return err
	}
	if err := releasebundle.VerifySignature(encoded, signature, publicKey); err != nil {
		return err
	}
	value, err := releasebundle.Decode(encoded)
	if err != nil {
		return err
	}
	if err := releasebundle.VerifyArtifacts(*directory, value); err != nil {
		return err
	}
	fmt.Printf("verified %s (%d artifacts)\n", value.Version, len(value.Artifacts))
	return nil
}

func writeNew(path string, content []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	completed := false
	defer func() {
		_ = file.Close()
		if !completed {
			_ = os.Remove(path)
		}
	}()
	if _, err := file.Write(content); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	completed = true
	return nil
}
