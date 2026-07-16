package installer

import (
	"context"
	"os"
	"os/exec"
)

type Runner interface {
	LookPath(string) (string, error)
	Run(context.Context, string, ...string) (string, error)
}

type ApplyRunner interface {
	Runner
	RunEnv(context.Context, []string, string, ...string) (string, error)
}

type OSRunner struct{}

func (OSRunner) LookPath(name string) (string, error) {
	return exec.LookPath(name)
}

func (OSRunner) Run(ctx context.Context, name string, arguments ...string) (string, error) {
	output, err := exec.CommandContext(ctx, name, arguments...).CombinedOutput()
	return string(output), err
}

func (OSRunner) RunEnv(ctx context.Context, environment []string, name string, arguments ...string) (string, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	command.Env = append(os.Environ(), environment...)
	output, err := command.CombinedOutput()
	return string(output), err
}
