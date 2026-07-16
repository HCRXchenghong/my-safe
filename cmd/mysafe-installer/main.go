package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/HCRXchenghong/my-safe/internal/installer"
	"github.com/HCRXchenghong/my-safe/internal/releasebundle"
)

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mysafe-installer:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("usage: mysafe-installer inspect|install|rollback|verify-bundle [options]")
	}
	switch arguments[0] {
	case "inspect", "plan":
		return inspect(ctx, arguments[1:])
	case "verify-bundle":
		return verifyBundle(arguments[1:])
	case "install":
		return install(ctx, arguments[1:])
	case "rollback":
		return rollback(ctx, arguments[1:])
	default:
		return fmt.Errorf("unknown command %q", arguments[0])
	}
}

func install(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("install", flag.ContinueOnError)
	root := flags.String("root", "/", "installation filesystem root")
	bundle := flags.String("bundle", ".", "signed release bundle directory")
	manifestPath := flags.String("manifest", "", "release manifest path; defaults inside bundle")
	signaturePath := flags.String("signature", "", "release signature path; defaults inside bundle")
	expectedVersion := flags.String("expected-version", "", "require this exact signed release version")
	controlURL := flags.String("control-url", "", "My Safe control-plane URL")
	tokenFile := flags.String("bootstrap-token-file", "", "one-time Agent bootstrap token file")
	gateway := flags.String("gateway", "auto", "Gateway selection: auto, enabled, or disabled")
	upstream := flags.String("upstream", "", "explicit Gateway upstream URL")
	gatewayPort := flags.Int("gateway-port", 0, "local Gateway port; zero selects a free port")
	architecture := flags.String("architecture", "", "override target architecture")
	allowExperimental := flags.Bool("allow-experimental", false, "allow experimental platform installation")
	allowDowngrade := flags.Bool("allow-downgrade", false, "explicitly allow installing an older signed release")
	dryRun := flags.Bool("dry-run", false, "verify and print the plan without modifying the system")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	selection := installer.GatewaySelection(strings.ToLower(strings.TrimSpace(*gateway)))
	if selection != installer.GatewayAuto && selection != installer.GatewayEnabled && selection != installer.GatewayDisabled {
		return errors.New("-gateway must be auto, enabled, or disabled")
	}
	result, err := installer.Apply(ctx, installer.ApplyOptions{
		Root:               *root,
		BundleDirectory:    *bundle,
		ManifestPath:       *manifestPath,
		SignaturePath:      *signaturePath,
		ExpectedVersion:    *expectedVersion,
		ControlURL:         *controlURL,
		BootstrapTokenFile: *tokenFile,
		Gateway:            selection,
		Upstream:           *upstream,
		GatewayPort:        *gatewayPort,
		Architecture:       *architecture,
		AllowExperimental:  *allowExperimental,
		AllowDowngrade:     *allowDowngrade,
		DryRun:             *dryRun,
	})
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(result); encodeErr != nil {
			return encodeErr
		}
	} else {
		fmt.Printf("Release: %s\nStatus: %s\nIntegration: %s\n", result.Version, result.Status, result.Inspection.Plan.Integration)
		if result.TransactionID != "" {
			fmt.Println("Transaction:", result.TransactionID)
		}
	}
	return err
}

func rollback(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("rollback", flag.ContinueOnError)
	root := flags.String("root", "/", "installation filesystem root")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	record, err := installer.RollbackLatest(ctx, *root, nil)
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if encodeErr := encoder.Encode(record); encodeErr != nil {
			return encodeErr
		}
	} else if record.ID != "" {
		fmt.Printf("Transaction %s: %s\n", record.ID, record.Status)
	}
	return err
}

func verifyBundle(arguments []string) error {
	flags := flag.NewFlagSet("verify-bundle", flag.ContinueOnError)
	directory := flags.String("bundle", ".", "release artifact directory")
	manifestPath := flags.String("manifest", "release-manifest.json", "manifest path")
	signaturePath := flags.String("signature", "release-manifest.sig", "signature path")
	publicPath := flags.String("public-key", "", "trusted release public key")
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
	manifest, err := releasebundle.Decode(encoded)
	if err != nil {
		return err
	}
	if err := releasebundle.VerifyArtifacts(*directory, manifest); err != nil {
		return err
	}
	fmt.Printf("verified release %s\n", manifest.Version)
	return nil
}

func inspect(ctx context.Context, arguments []string) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	root := flags.String("root", "/", "filesystem root to inspect")
	architecture := flags.String("architecture", "", "override detected architecture")
	jsonOutput := flags.Bool("json", false, "emit machine-readable JSON")
	gateway := flags.String("gateway", "auto", "Gateway selection: auto, enabled, or disabled")
	upstream := flags.String("upstream", "", "explicit Gateway upstream URL")
	gatewayPort := flags.Int("gateway-port", 0, "local Gateway port; zero selects a free port")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	selection := installer.GatewaySelection(strings.ToLower(strings.TrimSpace(*gateway)))
	if selection != installer.GatewayAuto && selection != installer.GatewayEnabled && selection != installer.GatewayDisabled {
		return errors.New("-gateway must be auto, enabled, or disabled")
	}
	inspection, err := installer.Inspect(ctx, installer.InspectOptions{
		Root:         *root,
		Architecture: *architecture,
		Plan: installer.PlanOptions{
			Gateway:     selection,
			Upstream:    *upstream,
			GatewayPort: *gatewayPort,
		},
	})
	if err != nil {
		return err
	}
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(inspection); err != nil {
			return err
		}
	} else {
		fmt.Printf("Platform: %s %s (%s), support=%s\n", inspection.Environment.OSID, inspection.Environment.OSVersion, inspection.Environment.Architecture, inspection.Environment.Support)
		fmt.Printf("Integration: %s, installable=%t\n", inspection.Plan.Integration, inspection.Plan.Installable)
		for _, step := range inspection.Plan.Steps {
			fmt.Println("  +", step)
		}
		for _, notice := range inspection.Plan.Notices {
			fmt.Println("  !", notice)
		}
		for _, blocker := range inspection.Plan.Blockers {
			fmt.Println("  x", blocker)
		}
	}
	if !inspection.Plan.Installable {
		return errors.New("environment is not installable; see blockers above")
	}
	return nil
}
