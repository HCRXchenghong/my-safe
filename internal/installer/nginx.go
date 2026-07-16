package installer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"
)

func applyNginxGateway(ctx context.Context, root string, runner ApplyRunner, transaction *fileTransaction, plan Plan) error {
	if plan.NginxConfig == "" || plan.Upstream == "" || plan.NginxReplacement == "" {
		return nil
	}
	path := rootPath(root, plan.NginxConfig)
	if !withinRoot(root, path) {
		return errors.New("Nginx configuration escapes installation root")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat Nginx configuration: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("selected Nginx configuration is not a regular file")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read Nginx configuration: %w", err)
	}
	pattern := regexp.MustCompile(`(?i)\bproxy_pass\s+` + regexp.QuoteMeta(plan.Upstream) + `\s*;`)
	matches := pattern.FindAllIndex(content, -1)
	if len(matches) != 1 {
		return fmt.Errorf("Nginx source changed since inspection: expected one proxy_pass, found %d", len(matches))
	}
	match := matches[0]
	replacement := []byte("proxy_pass " + plan.NginxReplacement + ";")
	updated := make([]byte, 0, len(content)-match[1]+match[0]+len(replacement))
	updated = append(updated, content[:match[0]]...)
	updated = append(updated, replacement...)
	updated = append(updated, content[match[1]:]...)
	if err := transaction.RecordNginxChange(); err != nil {
		return err
	}
	if err := transaction.InstallBytes(plan.NginxConfig, updated, info.Mode().Perm()); err != nil {
		return err
	}
	if err := runFixed(ctx, runner, "nginx", "-t"); err != nil {
		return fmt.Errorf("validate Nginx Gateway integration: %w", err)
	}
	if err := runFixed(ctx, runner, "systemctl", "reload", "nginx.service"); err != nil {
		return fmt.Errorf("reload Nginx Gateway integration: %w", err)
	}
	return nil
}
