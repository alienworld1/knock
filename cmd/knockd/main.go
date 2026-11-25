package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"knock/internal/command"
	"knock/internal/door"
	"knock/internal/lease"

	"github.com/spf13/cobra"
)

func main() { os.Exit(command.Run(root())) }

func root() *cobra.Command {
	var path string
	root := &cobra.Command{Use: "knockd", Short: "Operate an Approval Door"}
	root.PersistentFlags().StringVar(&path, "config", "", "Door configuration path")
	root.AddCommand(mailboxCommand(),
		&cobra.Command{
			Use: "register", Short: "Commit the Door policy and publish its signed Card", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				config, err := door.LoadConfig(path)
				if err != nil {
					return command.Exit(2, err)
				}
				if config.OwnerProfile == "" {
					return command.Exit(2, errors.New("set an owner profile in the Door configuration"))
				}
				owner, err := command.Unlock(config.OwnerProfile, "Owner passphrase")
				if err != nil {
					return command.Exit(8, err)
				}
				defer owner.Clear()
				keys, err := command.Unlock(config.DoorProfile, "Door passphrase")
				if err != nil {
					return command.Exit(8, err)
				}
				defer keys.Clear()
				ctx, cancel := context.WithTimeout(cmd.Context(), 140*time.Second)
				defer cancel()
				if err := door.Register(ctx, config, owner, keys, command.Progress); err != nil {
					return command.Exit(3, err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Door Card published")
				return nil
			},
		},
		&cobra.Command{
			Use: "serve", Short: "Verify a Door and receive private requests", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				config, err := door.LoadConfig(path)
				if err != nil {
					return command.Exit(2, err)
				}
				keys, err := command.SystemdUnlock(config.DoorProfile)
				if err != nil {
					return command.Exit(8, err)
				}
				defer keys.Clear()
				if config.Mailbox != "" && config.Policy.Enabled {
					return serveAdmission(cmd, config, keys)
				}
				return command.Exit(3, door.Serve(cmd.Context(), config, keys, command.Progress))
			},
		},
	)
	root.AddCommand(
		&cobra.Command{
			Use: "expire-ssh <session>", Hidden: true, Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				call, cancel := context.WithTimeout(cmd.Context(), 25*time.Second)
				defer cancel()
				if err := lease.Expire(call, args[0]); err != nil {
					return command.Exit(7, fmt.Errorf("Session %s · Cleanup incomplete: %w", args[0], err))
				}
				fmt.Fprintln(cmd.OutOrStdout(), "SSH expiry cleanup completed")
				return nil
			},
		},
		&cobra.Command{
			Use: "ssh-role <role> <session>", Hidden: true, Args: cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				return command.Exit(1, lease.Role(args[0], args[1], os.Getenv("SSH_ORIGINAL_COMMAND"), cmd.InOrStdin(), cmd.OutOrStdout()))
			},
		},
		&cobra.Command{
			Use: "ssh-workload", Hidden: true, Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				return command.Exit(1, lease.LaunchWorkload())
			},
		},
	)
	return root
}
