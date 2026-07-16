package installer

type SupportLevel string

const (
	SupportStable       SupportLevel = "stable"
	SupportExperimental SupportLevel = "experimental"
	SupportUnsupported  SupportLevel = "unsupported"
)

type Tool struct {
	Available bool   `json:"available"`
	Version   string `json:"version,omitempty"`
}

type ProxyCandidate struct {
	ConfigPath string `json:"config_path"`
	Upstream   string `json:"upstream"`
	Port       int    `json:"port"`
	Directive  string `json:"directive"`
}

type Environment struct {
	OSID            string           `json:"os_id"`
	OSVersion       string           `json:"os_version"`
	OSCodename      string           `json:"os_codename,omitempty"`
	Architecture    string           `json:"architecture"`
	Support         SupportLevel     `json:"support"`
	Systemd         Tool             `json:"systemd"`
	Nginx           Tool             `json:"nginx"`
	Docker          Tool             `json:"docker"`
	DockerCompose   Tool             `json:"docker_compose"`
	ListeningPorts  []int            `json:"listening_ports,omitempty"`
	ProxyCandidates []ProxyCandidate `json:"proxy_candidates,omitempty"`
	Warnings        []string         `json:"warnings,omitempty"`
}

type GatewaySelection string

const (
	GatewayAuto     GatewaySelection = "auto"
	GatewayEnabled  GatewaySelection = "enabled"
	GatewayDisabled GatewaySelection = "disabled"
)

type PlanOptions struct {
	Gateway     GatewaySelection
	Upstream    string
	GatewayPort int
}

type Plan struct {
	Installable      bool         `json:"installable"`
	Support          SupportLevel `json:"support"`
	Integration      string       `json:"integration"`
	GatewayEnabled   bool         `json:"gateway_enabled"`
	GatewayListen    string       `json:"gateway_listen,omitempty"`
	Upstream         string       `json:"upstream,omitempty"`
	NginxConfig      string       `json:"nginx_config,omitempty"`
	NginxReplacement string       `json:"nginx_replacement,omitempty"`
	Steps            []string     `json:"steps"`
	Blockers         []string     `json:"blockers,omitempty"`
	Notices          []string     `json:"notices,omitempty"`
}

type Inspection struct {
	Environment Environment `json:"environment"`
	Plan        Plan        `json:"plan"`
}
