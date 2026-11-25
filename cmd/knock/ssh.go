package main

import (
	"errors"
	"fmt"
	"io"
	"os/exec"

	"knock/internal/command"
	"knock/internal/lease"

	"github.com/spf13/cobra"
)

func tunnelCommand(action string) *cobra.Command {
	return &cobra.Command{
		Use: "tunnel-" + action + " <interface>", Hidden: true, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return command.Exit(6, lease.Tunnel(cmd.Context(), action, args[0], cmd.InOrStdin()))
		},
	}
}

func sshExit(err error, stderr io.Writer) error {
	var native *exec.ExitError
	if errors.As(err, &native) && native.ExitCode() > 0 {
		if errors.Is(err, lease.ErrClientCleanup) {
			fmt.Fprintln(stderr, lease.ErrClientCleanup)
		}
		return command.SilentExit(native.ExitCode())
	}
	if errors.Is(err, lease.ErrClientCleanup) {
		return command.Exit(7, err)
	}
	return command.Exit(6, err)
}
