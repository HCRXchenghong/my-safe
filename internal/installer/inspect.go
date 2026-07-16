package installer

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
)

type InspectOptions struct {
	Root         string
	Architecture string
	Runner       Runner
	Plan         PlanOptions
}

var literalProxyPass = regexp.MustCompile(`(?i)\bproxy_pass\s+(https?://(?:127\.0\.0\.1|localhost|\[::1\]):([0-9]{1,5})(?:/[^;\s]*)?)\s*;`)

func Inspect(ctx context.Context, options InspectOptions) (Inspection, error) {
	if options.Root == "" {
		options.Root = string(filepath.Separator)
	}
	root, err := filepath.Abs(options.Root)
	if err != nil {
		return Inspection{}, fmt.Errorf("resolve inspection root: %w", err)
	}
	if options.Runner == nil {
		options.Runner = OSRunner{}
	}
	architecture := options.Architecture
	if architecture == "" {
		architecture = runtime.GOARCH
	}
	environment := Environment{Architecture: normalizeArchitecture(architecture)}
	osRelease, err := os.ReadFile(rootPath(root, "/etc/os-release"))
	if err != nil {
		return Inspection{}, fmt.Errorf("read /etc/os-release: %w", err)
	}
	fields := parseOSRelease(osRelease)
	environment.OSID = strings.ToLower(fields["ID"])
	environment.OSVersion = fields["VERSION_ID"]
	environment.OSCodename = firstNonEmpty(fields["VERSION_CODENAME"], fields["UBUNTU_CODENAME"])
	environment.Support = supportLevel(environment.OSID, environment.OSVersion, environment.Architecture)

	environment.Systemd = inspectTool(ctx, options.Runner, "systemctl", "--version")
	environment.Nginx = inspectTool(ctx, options.Runner, "nginx", "-v")
	environment.Docker = inspectTool(ctx, options.Runner, "docker", "version", "--format", "{{.Server.Version}}")
	if environment.Docker.Available {
		environment.DockerCompose = inspectTool(ctx, options.Runner, "docker", "compose", "version", "--short")
	}
	environment.ListeningPorts = inspectListeningPorts(root)
	environment.ProxyCandidates, environment.Warnings = inspectNginx(root)
	plan := BuildPlan(environment, options.Plan)
	return Inspection{Environment: environment, Plan: plan}, nil
}

func inspectTool(ctx context.Context, runner Runner, name string, arguments ...string) Tool {
	if _, err := runner.LookPath(name); err != nil {
		return Tool{}
	}
	output, err := runner.Run(ctx, name, arguments...)
	version := firstOutputLine(output)
	return Tool{Available: err == nil || version != "", Version: version}
}

func inspectListeningPorts(root string) []int {
	ports := make(map[int]struct{})
	for _, name := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		content, err := os.ReadFile(rootPath(root, name))
		if err != nil {
			continue
		}
		for _, port := range parseListeningPorts(content) {
			ports[port] = struct{}{}
		}
	}
	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}

func inspectNginx(root string) ([]ProxyCandidate, []string) {
	nginxRoot := rootPath(root, "/etc/nginx")
	candidates := make([]ProxyCandidate, 0)
	warnings := make([]string, 0)
	seenFiles := 0
	inspectedFiles := make(map[string]bool)
	err := filepath.WalkDir(nginxRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			warnings = append(warnings, fmt.Sprintf("cannot inspect %s", displayPath(root, path)))
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		if seenFiles >= 1000 {
			return fs.SkipAll
		}
		display := displayPath(root, path)
		if !strings.HasSuffix(strings.ToLower(entry.Name()), ".conf") && entry.Name() != "nginx.conf" && !strings.Contains(display, "/sites-enabled/") {
			return nil
		}
		seenFiles++
		content, actualPath, err := readConfigFile(root, path, entry)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("cannot read %s", displayPath(root, path)))
			return nil
		}
		actualPath = filepath.Clean(actualPath)
		if inspectedFiles[actualPath] {
			return nil
		}
		inspectedFiles[actualPath] = true
		scanner := bufio.NewScanner(bytes.NewReader(content))
		for scanner.Scan() {
			line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
			for _, match := range literalProxyPass.FindAllStringSubmatch(line, -1) {
				port, err := strconv.Atoi(match[2])
				if err != nil || port < 1 || port > 65535 {
					continue
				}
				candidates = append(candidates, ProxyCandidate{
					ConfigPath: displayPath(root, actualPath),
					Upstream:   match[1],
					Port:       port,
					Directive:  match[0],
				})
			}
		}
		return nil
	})
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		warnings = append(warnings, "cannot traverse /etc/nginx")
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].ConfigPath == candidates[j].ConfigPath {
			return candidates[i].Upstream < candidates[j].Upstream
		}
		return candidates[i].ConfigPath < candidates[j].ConfigPath
	})
	sort.Strings(warnings)
	return candidates, warnings
}

func readConfigFile(root, path string, entry fs.DirEntry) ([]byte, string, error) {
	if entry.Type()&os.ModeSymlink == 0 {
		content, err := os.ReadFile(path)
		return content, path, err
	}
	target, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, "", err
	}
	if !withinRoot(root, target) {
		return nil, "", errors.New("nginx symlink escapes inspection root")
	}
	content, err := os.ReadFile(target)
	return content, target, err
}

func BuildPlan(environment Environment, options PlanOptions) Plan {
	if options.Gateway == "" {
		options.Gateway = GatewayAuto
	}
	if options.GatewayPort == 0 {
		usedPorts := append([]int(nil), environment.ListeningPorts...)
		for _, candidate := range environment.ProxyCandidates {
			usedPorts = append(usedPorts, candidate.Port)
		}
		options.GatewayPort = firstFreePort(usedPorts, 18081, 18180)
	}
	plan := Plan{
		Support:     environment.Support,
		Integration: "sensor",
		Steps:       []string{},
		Blockers:    []string{},
		Notices:     []string{},
	}
	if environment.Support == SupportUnsupported {
		plan.Blockers = append(plan.Blockers, fmt.Sprintf("unsupported platform %s %s/%s", environment.OSID, environment.OSVersion, environment.Architecture))
	}
	if !environment.Systemd.Available {
		plan.Blockers = append(plan.Blockers, "systemd is required for the native Agent service")
	}
	if len(plan.Blockers) > 0 {
		return plan
	}
	plan.Installable = true
	plan.Steps = append(plan.Steps,
		"verify signed release manifest and artifact hashes",
		"install Agent binary and hardened systemd unit",
		"register Agent with the one-time bootstrap token",
		"run a read-only baseline scan and verify heartbeat",
	)
	if environment.Support == SupportExperimental {
		plan.Notices = append(plan.Notices, "platform is experimental and requires explicit confirmation")
	}
	if options.Gateway == GatewayDisabled {
		plan.Notices = append(plan.Notices, "Gateway disabled by operator; Sensor protection remains active")
		return plan
	}

	upstream := strings.TrimSpace(options.Upstream)
	nginxConfig := ""
	if upstream != "" {
		if err := validateUpstream(upstream); err != nil {
			plan.Blockers = append(plan.Blockers, err.Error())
			if options.Gateway == GatewayEnabled {
				plan.Installable = false
			}
			return plan
		}
	} else if len(environment.ProxyCandidates) == 1 {
		upstream = environment.ProxyCandidates[0].Upstream
		nginxConfig = environment.ProxyCandidates[0].ConfigPath
	} else {
		if len(environment.ProxyCandidates) == 0 {
			plan.Notices = append(plan.Notices, "no unique literal loopback Nginx proxy_pass was found; staying in Sensor mode")
		} else {
			plan.Notices = append(plan.Notices, "multiple Nginx upstreams were found; staying in Sensor mode until an upstream is selected")
		}
		if options.Gateway == GatewayEnabled {
			plan.Installable = false
			plan.Blockers = append(plan.Blockers, "Gateway was required but no unambiguous upstream is available")
		}
		return plan
	}
	if options.GatewayPort == 0 {
		plan.Notices = append(plan.Notices, "no free Gateway port is available in 18081-18180; staying in Sensor mode")
		if options.Gateway == GatewayEnabled {
			plan.Installable = false
			plan.Blockers = append(plan.Blockers, "Gateway was required but no local listen port is available")
		}
		return plan
	}
	plan.GatewayEnabled = true
	plan.Integration = "nginx_gateway"
	plan.GatewayListen = fmt.Sprintf("127.0.0.1:%d", options.GatewayPort)
	plan.Upstream = upstream
	plan.NginxConfig = nginxConfig
	if nginxConfig != "" {
		plan.NginxReplacement = fmt.Sprintf("http://127.0.0.1:%d", options.GatewayPort)
	}
	plan.Steps = append(plan.Steps,
		"install Gateway in observe mode",
		"health-check Gateway against the detected upstream",
	)
	if nginxConfig != "" {
		plan.Steps = append(plan.Steps,
			"back up and hash the selected Nginx configuration",
			"replace the single proxy_pass with the local Gateway",
			"run nginx -t, reload, and verify the protected route",
		)
	} else {
		plan.Notices = append(plan.Notices, "explicit upstream selected; external ingress still needs an explicit routing step")
	}
	return plan
}

func validateUpstream(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return errors.New("explicit Gateway upstream must be an absolute HTTP(S) URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return errors.New("explicit Gateway upstream scheme must be http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("explicit Gateway upstream must not contain credentials, query, or fragment")
	}
	return nil
}

func supportLevel(osID, version, architecture string) SupportLevel {
	if architecture != "amd64" && architecture != "arm64" {
		return SupportUnsupported
	}
	switch osID {
	case "ubuntu":
		switch majorMinor(version) {
		case "22.04", "24.04":
			return SupportStable
		case "26.04":
			return SupportExperimental
		}
	case "debian":
		switch majorMinor(version) {
		case "12", "13":
			return SupportStable
		}
	}
	return SupportUnsupported
}

func normalizeArchitecture(architecture string) string {
	switch strings.ToLower(strings.TrimSpace(architecture)) {
	case "x86_64", "x64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	default:
		return strings.ToLower(strings.TrimSpace(architecture))
	}
}

func parseOSRelease(content []byte) map[string]string {
	result := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), "\"")
		result[strings.TrimSpace(key)] = value
	}
	return result
}

func parseListeningPorts(content []byte) []int {
	ports := make(map[int]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 4 || fields[3] != "0A" {
			continue
		}
		_, rawPort, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(rawPort, 16, 16)
		if err == nil && port > 0 {
			ports[int(port)] = struct{}{}
		}
	}
	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)
	return result
}

func firstFreePort(used []int, start, end int) int {
	occupied := make(map[int]bool, len(used))
	for _, port := range used {
		occupied[port] = true
	}
	for port := start; port <= end; port++ {
		if !occupied[port] {
			return port
		}
	}
	return 0
}

func firstOutputLine(output string) string {
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			if len(line) > 256 {
				return line[:256]
			}
			return line
		}
	}
	return ""
}

func rootPath(root, unixPath string) string {
	return filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(unixPath, "/")))
}

func displayPath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return "/" + filepath.ToSlash(relative)
}

func withinRoot(root, path string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func majorMinor(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return version
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
