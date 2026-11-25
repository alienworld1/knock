package lease

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

const (
	ipPath         = "/usr/sbin/ip"
	wgPath         = "/usr/bin/wg"
	nftPath        = "/usr/sbin/nft"
	sshdPath       = "/usr/sbin/sshd"
	systemctlPath  = "/usr/bin/systemctl"
	systemdRunPath = "/usr/bin/systemd-run"
	journalPath    = "/usr/bin/journalctl"
	daemonPath     = "/usr/local/bin/knockd"
)

func native(ctx context.Context, input []byte, path string, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(call, path, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin", "LANG=C"}
	if input != nil {
		cmd.Stdin = bytes.NewReader(input)
	}
	out, err := cmd.Output()
	if err != nil {
		// Native stderr may contain input or private network configuration.
		return nil, fmt.Errorf("%s %s: %w", path, args[0], err)
	}
	return out, nil
}

func run(ctx context.Context, path string, args ...string) error {
	_, err := native(ctx, nil, path, args...)
	return err
}
