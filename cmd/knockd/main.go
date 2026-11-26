package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"knock/internal/admission"
	"knock/internal/command"
	"knock/internal/door"
	"knock/internal/lease"
	"knock/internal/protocol"

	"github.com/spf13/cobra"
)

func main() { os.Exit(command.Run(root())) }

func root() *cobra.Command {
	var path string
	root := &cobra.Command{
		Use:   "knockd",
		Short: "Operate a Knock Door",
		Example: `  knockd register --config door.json
  knockd serve --config /etc/knock/door.json
  knockd mailbox --state mailbox.db`,
	}
	root.PersistentFlags().StringVar(&path, "config", "", "Door configuration path")
	root.AddCommand(mailboxCommand(), auditExportCommand(&path),
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
				var ssh *lease.Host
				if config.WireGuardEndpoint != "" {
					ssh, err = reconcileSSH(cmd.Context(), config)
					if err != nil {
						return command.Exit(7, err)
					}
					defer ssh.Release()
				}
				keys, err := command.SystemdUnlock(config.DoorProfile)
				if err != nil {
					return command.Exit(8, err)
				}
				defer keys.Clear()
				if config.Mailbox != "" && config.Policy.Enabled {
					return serveAdmission(cmd, config, keys, ssh)
				}
				return command.Exit(3, door.Serve(cmd.Context(), config, keys, command.Progress))
			},
		},
	)
	root.AddCommand(
		&cobra.Command{
			Use: "reconcile", Short: "Close outstanding sessions on a stopped Door", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				config, err := door.LoadConfig(path)
				if err != nil {
					return command.Exit(2, err)
				}
				if config.WireGuardEndpoint == "" {
					return command.Exit(2, errors.New("the Door has no configured WireGuard service"))
				}
				ssh, err := reconcileSSH(cmd.Context(), config)
				if err != nil {
					return command.Exit(7, err)
				}
				defer ssh.Release()
				fmt.Fprintln(cmd.OutOrStdout(), "Host cleanup verified")
				return nil
			},
		},
		&cobra.Command{
			Use: "expire-ssh <session>", Hidden: true, Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				call, cancel := context.WithTimeout(cmd.Context(), 25*time.Second)
				defer cancel()
				if err := lease.Expire(call, args[0]); err != nil {
					return command.Exit(7, fmt.Errorf("Session %s · Cleanup incomplete: %w", args[0], err))
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Session expiry cleanup completed")
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
		&cobra.Command{
			Use: "private-http <slot>", Hidden: true, Args: cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return command.Exit(6, lease.ServeHTTP(args[0], cmd.OutOrStdout()))
			},
		},
	)
	return root
}

// Deny and verify host resources before depending on credentials, chain or Mailbox.
func reconcileSSH(ctx context.Context, config door.Config) (*lease.Host, error) {
	call, cancel := context.WithTimeout(ctx, 75*time.Second)
	defer cancel()
	ssh, cleanup := lease.StartHost(call, config.WireGuardEndpoint, config.Policy.Offer != nil)
	if cleanup != nil {
		if !errors.Is(cleanup, lease.ErrDoorLocked) {
			command.Progress("Host cleanup incomplete. Admissions remain closed.")
		}
		return nil, cleanup
	}
	db, err := protocol.OpenState(config.State)
	if err == nil {
		defer db.Close()
		var journal *admission.Journal
		journal, err = admission.NewJournal(db)
		if err == nil {
			err = (admission.Host{Journal: journal, Progress: command.Progress}).ReconcileSSH("Door restarted", true)
		}
	}
	if err != nil {
		ssh.Release()
		return nil, err
	}
	return ssh, nil
}
