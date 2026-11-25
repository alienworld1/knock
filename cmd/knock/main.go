package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"knock/internal/admission"
	"knock/internal/chain"
	"knock/internal/command"
	"knock/internal/door"
	"knock/internal/identity"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

type settings struct {
	profile string
	network string
	cards   string
	home    string
	mailbox string
}

func main() { os.Exit(command.Run(root())) }

func root() *cobra.Command {
	s := &settings{home: command.Home()}
	root := &cobra.Command{Use: "knock", Short: "Request or review private access on Diana"}
	root.PersistentFlags().StringVar(&s.profile, "profile", "", "encrypted identity profile")
	root.PersistentFlags().StringVar(&s.network, "network", "", "pinned registry configuration")
	root.PersistentFlags().StringVar(&s.cards, "cards", "", "directory containing signed Door Cards")
	root.PersistentFlags().StringVar(&s.mailbox, "mailbox", "", "Mailbox origin for operator commands")
	s.requestFlags(root)
	root.AddCommand(tunnelCommand("up"), tunnelCommand("down"))
	root.AddCommand(s.identityCommands(), s.doorCommands(), s.revokeCommand(), s.requestsCommand(),
		s.decisionCommand("approve", admission.Authorized), s.decisionCommand("deny", admission.Denied))
	return root
}

func (s *settings) identityCommands() *cobra.Command {
	identityCommand := &cobra.Command{Use: "identity", Short: "Manage your Diana identity"}
	identityCommand.AddCommand(
		&cobra.Command{
			Use: "init", Short: "Create an encrypted Diana identity", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				path := command.Profile(s.home, s.profile)
				if path == "" {
					return command.Exit(2, errors.New("set an identity profile path"))
				}
				pass, err := command.NewPassphrase()
				if err != nil {
					return command.Exit(2, err)
				}
				defer clear(pass)
				account, err := identity.Init(path, pass)
				if err != nil {
					return command.Exit(8, err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), account.Bech32)
				return nil
			},
		},
		&cobra.Command{
			Use: "register", Short: "Register signing and recipient keys on Diana", Args: cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				keys, err := command.Unlock(command.Profile(s.home, s.profile), "Identity passphrase")
				if err != nil {
					return command.Exit(8, err)
				}
				defer keys.Clear()
				ctx, cancel := context.WithTimeout(cmd.Context(), 100*time.Second)
				defer cancel()
				card, err := chain.Diana().Register(ctx, keys, command.Progress)
				if err != nil {
					return command.Exit(3, err)
				}
				return command.Exit(8, json.NewEncoder(cmd.OutOrStdout()).Encode(card))
			},
		},
	)
	identityCommand.AddCommand(s.publishRecipientCommand())
	return identityCommand
}

func (s *settings) doorCommands() *cobra.Command {
	group := &cobra.Command{Use: "door", Short: "Trust and inspect Doors"}
	var alias string
	trust := &cobra.Command{
		Use: "trust <account>", Short: "Save a verified account as a local alias", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if s.home == "" || !door.IsAlias(alias) {
				return command.Exit(2, errors.New("set a local profile directory and an alias using lowercase letters, numbers, or hyphens"))
			}
			if _, err := door.ParseAccount(args[0]); err != nil {
				return command.Exit(2, err)
			}
			return s.withDoor(cmd, args[0], func(_ context.Context, _ *chain.EVM, card door.Card) error {
				data := door.Alias{Account: card.Details.Account, SigningKey: card.Details.SigningKey}
				if err := door.SaveAlias(filepath.Join(s.home, "aliases"), alias, data); err != nil {
					return command.Exit(8, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s %s\n", alias, data.Account)
				return nil
			})
		},
	}
	trust.Flags().StringVar(&alias, "alias", "", "local alias")
	var asJSON bool
	var revocation string
	show := &cobra.Command{
		Use: "show <door>", Short: "Verify the current Door Card and policy", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var session common.Hash
			if revocation != "" {
				if err := session.UnmarshalText([]byte(revocation)); err != nil || session == (common.Hash{}) {
					return command.Exit(2, errors.New("expected a nonzero 32-byte session reference in hex"))
				}
			}
			return s.withDoor(cmd, args[0], func(ctx context.Context, evm *chain.EVM, card door.Card) error {
				d := card.Details
				result := struct {
					Version    uint64      `json:"version"`
					Account    string      `json:"account"`
					Owner      string      `json:"owner"`
					DoorID     common.Hash `json:"doorId"`
					SigningKey common.Hash `json:"signingKey"`
					Policy     door.Policy `json:"policy"`
					Revoked    *bool       `json:"revoked,omitempty"`
				}{Version: 1, Account: d.Account, Owner: d.Owner, DoorID: d.DoorID, SigningKey: d.SigningKey, Policy: d.Policy}
				if session != (common.Hash{}) {
					revoked, err := evm.Revoked(ctx, d.Registry, d.DoorID, session)
					if err != nil {
						return command.Exit(3, err)
					}
					result.Revoked = &revoked
				}
				if asJSON {
					return command.Exit(8, json.NewEncoder(cmd.OutOrStdout()).Encode(result))
				}
				state := "Approval required"
				if !d.Policy.Enabled {
					state = "Disabled"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Door %s\n%s · Policy %d\nRoles %s · Limit %s\n",
					d.Account, state, d.Policy.Version, strings.Join(d.Policy.Roles, ", "),
					time.Duration(d.Policy.MaxDurationSeconds)*time.Second)
				if result.Revoked != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "Registry revoked %t\n", *result.Revoked)
				}
				return nil
			})
		},
	}
	show.Flags().BoolVar(&asJSON, "json", false, "write verified Door details as JSON")
	show.Flags().StringVar(&revocation, "revocation", "", "inspect a session reference in the registry")
	group.AddCommand(trust, show)
	return group
}

func (s *settings) revokeCommand() *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use: "revoke <session-id>", Short: "Revoke a session reference on Diana", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var session common.Hash
			if target == "" || session.UnmarshalText([]byte(args[0])) != nil || session == (common.Hash{}) {
				return command.Exit(2, errors.New("set --door and a nonzero 32-byte session reference in hex"))
			}
			return s.withDoor(cmd, target, func(ctx context.Context, evm *chain.EVM, card door.Card) error {
				keys, err := command.Unlock(command.Profile(s.home, s.profile), "Identity passphrase")
				if err != nil {
					return command.Exit(8, err)
				}
				defer keys.Clear()
				if err := evm.Revoke(ctx, card.Details.Registry, card.Details.DoorID, session, keys, command.Progress); err != nil {
					return command.Exit(3, err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Registry revocation confirmed")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&target, "door", "", "trusted Door account or alias")
	return cmd
}

func (s *settings) withDoor(cmd *cobra.Command, target string, use func(context.Context, *chain.EVM, door.Card) error) error {
	pin, err := s.registry()
	if err != nil {
		return command.Exit(2, err)
	}
	var alias *door.Alias
	if !strings.HasPrefix(target, "qor1") {
		record, err := door.ReadAlias(filepath.Join(s.home, "aliases"), target)
		if err != nil {
			return command.Exit(8, fmt.Errorf("read Door alias: %w", err))
		}
		target = record.Account
		alias = &record
	}
	card, err := door.ReadCard(s.cardsDirectory(), target)
	if err != nil {
		return command.Exit(3, err)
	}
	if alias != nil && alias.SigningKey != common.Hash(card.Details.SigningKey) {
		return command.Exit(3, errors.New("Door signing key changed. Verify the account before trusting a new alias."))
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 120*time.Second)
	defer cancel()
	native := chain.Diana()
	evm, err := chain.Connect(ctx, native)
	if err != nil {
		return command.Exit(3, err)
	}
	defer evm.Close()
	if err := card.Verify(ctx, native, evm, pin, target); err != nil {
		return command.Exit(3, err)
	}
	return use(ctx, evm, card)
}

func (s *settings) registry() (chain.Registry, error) {
	var pin struct {
		Registry chain.Registry `json:"registry"`
	}
	network := s.network
	if network == "" && s.home != "" {
		network = filepath.Join(s.home, "network.json")
	}
	if err := door.ReadConfig(network, &pin); err != nil {
		return chain.Registry{}, fmt.Errorf("load registry configuration: %w", err)
	}
	return pin.Registry, nil
}

func (s *settings) cardsDirectory() string {
	if s.cards == "" && s.home != "" {
		return filepath.Join(s.home, "cards")
	}
	return s.cards
}
