package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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
	root := &cobra.Command{
		Use:   "knock",
		Short: "Temporary, verified access to private Linux servers",
		Example: `  knock validator-ops --ssh --role logs --for 15m --reason -
  knock private-status --tunnel --pay 2m
  knock console`,
	}
	root.PersistentFlags().StringVar(&s.profile, "profile", "", "encrypted identity profile")
	root.PersistentFlags().StringVar(&s.network, "network", "", "pinned registry configuration")
	root.PersistentFlags().StringVar(&s.cards, "cards", "", "directory containing signed Door Cards")
	root.PersistentFlags().StringVar(&s.mailbox, "mailbox", "", "Mailbox origin for operator commands")
	s.requestFlags(root)
	root.AddCommand(tunnelCommand("up"), tunnelCommand("down"))
	root.AddCommand(s.identityCommands(), s.doorCommands(), s.revokeCommand(), s.sessionsCommand(), s.auditCommand(), s.historyCommand(), s.requestsCommand(), s.paymentCommand(),
		s.decisionCommand("approve", admission.Authorized), s.decisionCommand("deny", admission.Denied), s.consoleCommand())
	return root
}

func (s *settings) identityCommands() *cobra.Command {
	identityCommand := &cobra.Command{Use: "identity", Short: "Manage your local identity"}
	identityCommand.AddCommand(
		&cobra.Command{
			Use: "init", Short: "Create an encrypted identity profile", Args: cobra.NoArgs,
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
				command.Info(cmd.ErrOrStderr(), "Fund this address on Diana testnet, then run: knock identity register")
				return nil
			},
		},
		&cobra.Command{
			Use: "register", Short: "Register signing and encryption keys on Diana", Args: cobra.NoArgs,
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
		Use: "trust <account>", Short: "Save a verified Door account as a local alias", Args: cobra.ExactArgs(1),
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
				command.OK(cmd.ErrOrStderr(), fmt.Sprintf("Trusted %s as %s", data.Account, alias))
				return nil
			})
		},
	}
	trust.Flags().StringVar(&alias, "alias", "", "local alias")
	var asJSON bool
	var revocation string
	show := &cobra.Command{
		Use: "show <door>", Short: "Verify and inspect a Door Card and policy", Args: cobra.ExactArgs(1),
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
				if d.Mode == door.Metered {
					state = "Purchase required"
				}
				if !d.Policy.Enabled {
					state = "Disabled"
				}
				out := cmd.OutOrStdout()
				modeLabel := "Approval"
				if d.Mode == door.Metered {
					modeLabel = "Metered"
				}
				command.Field(out, "Door", d.Account)
				command.Field(out, "Status", state)
				command.Field(out, "Policy", fmt.Sprintf("v%d", d.Policy.Version))
				command.Field(out, "Mode", modeLabel)
				duration := time.Duration(d.Policy.MaxDurationSeconds) * time.Second
				if offer := d.Policy.Offer; offer != nil {
					command.Field(out, "Service", offer.Service)
					command.Field(out, "Duration", command.Duration(duration))
					command.Field(out, "Price", formatQOR(offer.PriceUQOR)+" test QOR")
				} else {
					command.Field(out, "Roles", strings.Join(d.Policy.Roles, ", "))
					command.Field(out, "Limit", command.Duration(duration))
				}
				command.Field(out, "Signing key", common.Hash(d.SigningKey).Hex())
				command.Field(out, "Registry", d.Registry.Address.Hex())
				if result.Revoked != nil {
					command.Field(out, "Registry revoked", fmt.Sprintf("%t", *result.Revoked))
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
		Use: "revoke <session-id>", Short: "Revoke a session on Diana", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var session common.Hash
			if session.UnmarshalText([]byte(args[0])) != nil || session == (common.Hash{}) {
				return command.Exit(2, errors.New("set a nonzero 32-byte session reference in hex"))
			}
			selected, err := s.sessionDoor(target)
			if err != nil {
				return command.Exit(2, err)
			}
			keys, err := command.Unlock(command.Profile(s.home, s.profile), "Identity passphrase")
			if err != nil {
				return command.Exit(8, err)
			}
			defer keys.Clear()
			if err := s.revoke(cmd.Context(), selected, session, keys, command.Progress); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Revocation confirmed on Diana. Check session status for host cleanup.")
			return nil
		},
	}
	cmd.Flags().StringVar(&target, "door", "", "trusted Door account or alias")
	return cmd
}

func (s *settings) withDoor(cmd *cobra.Command, target string, use func(context.Context, *chain.EVM, door.Card) error) error {
	return s.withVerifiedDoor(cmd.Context(), target, use)
}

func (s *settings) withVerifiedDoor(ctx context.Context, target string, use func(context.Context, *chain.EVM, door.Card) error) error {
	card, pin, _, err := s.localDoor(target)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	native := chain.Diana()
	evm, err := chain.Connect(ctx, native)
	if err != nil {
		return command.Exit(3, err)
	}
	defer evm.Close()
	if err := card.Verify(ctx, native, evm, pin, card.Details.Account); err != nil {
		return command.Exit(3, err)
	}
	return use(ctx, evm, card)
}

func canRevoke(card door.Card, account string) bool {
	d := card.Details
	return d.Owner == account || (d.Policy.ApproversCanRevoke && slices.Contains(d.Policy.Approvers, account))
}

func (s *settings) revoke(ctx context.Context, target string, session common.Hash, keys *identity.Keys, report func(string)) error {
	return s.withVerifiedDoor(ctx, target, func(ctx context.Context, evm *chain.EVM, card door.Card) error {
		return revokeVerified(ctx, evm, card, session, keys, report)
	})
}

func revokeVerified(ctx context.Context, evm *chain.EVM, card door.Card, session common.Hash, keys *identity.Keys, report func(string)) error {
	if !canRevoke(card, keys.Account.Bech32) {
		return command.Exit(3, errOperatorUnauthorized)
	}
	return command.Exit(3, evm.Revoke(ctx, card.Details.Registry, card.Details.DoorID, session, keys, report))
}

var errOperatorUnauthorized = errors.New("this identity is not authorized for that action")

// localDoor reads the configured Card and checks the pin recorded by door trust.
func (s *settings) localDoor(target string) (door.Card, chain.Registry, bool, error) {
	pin, err := s.registry()
	if err != nil {
		return door.Card{}, chain.Registry{}, false, command.Exit(2, err)
	}
	var alias *door.Alias
	if !strings.HasPrefix(target, "qor1") {
		record, err := door.ReadAlias(filepath.Join(s.home, "aliases"), target)
		if err != nil {
			return door.Card{}, chain.Registry{}, false, command.Exit(8, fmt.Errorf("read Door alias: %w", err))
		}
		target = record.Account
		alias = &record
	}
	card, err := door.ReadCard(s.cardsDirectory(), target)
	if err != nil {
		return door.Card{}, chain.Registry{}, false, command.Exit(3, err)
	}
	if alias != nil && alias.SigningKey != common.Hash(card.Details.SigningKey) {
		return door.Card{}, chain.Registry{}, false, command.Exit(3, errors.New("Door signing key changed. Verify the account before trusting a new alias."))
	}
	if card.Details.Registry != pin || card.Details.Account != target {
		return door.Card{}, chain.Registry{}, false, command.Exit(3, errors.New("Door Card does not match the configured account or registry"))
	}
	return card, pin, alias != nil, nil
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
