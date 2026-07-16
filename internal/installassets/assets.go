package installassets

import "embed"

//go:embed systemd/*.service release-public-key.pem
var files embed.FS

func AgentUnit() ([]byte, error) {
	return files.ReadFile("systemd/my-safe-agent.service")
}

func GatewayUnit() ([]byte, error) {
	return files.ReadFile("systemd/my-safe-gateway.service")
}

func ReleasePublicKey() ([]byte, error) {
	return files.ReadFile("release-public-key.pem")
}
