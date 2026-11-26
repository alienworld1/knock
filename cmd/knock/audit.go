package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"

	"knock/internal/admission"
	"knock/internal/chain"
	"knock/internal/command"
	"knock/internal/door"
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"
)

func (s *settings) auditCommand() *cobra.Command {
	audit := &cobra.Command{Use: "audit", Short: "Manage audit membership"}
	var target string
	var members []string
	var epoch uint64
	var clearMembers bool
	rotate := &cobra.Command{
		Use: "rotate", Short: "Queue an owner-signed audit membership change", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if target == "" || !cmd.Flags().Changed("epoch") || epoch == ^uint64(0) ||
				(!clearMembers && len(members) == 0) || (clearMembers && len(members) != 0) {
				return command.Exit(2, errors.New("set --door, --epoch and the complete list of --member accounts or --clear"))
			}
			return s.withDoor(cmd, target, func(ctx context.Context, _ *chain.EVM, card door.Card) error {
				keys, err := command.Unlock(command.Profile(s.home, s.profile), "Owner passphrase")
				if err != nil {
					return command.Exit(8, err)
				}
				defer keys.Clear()
				relay, err := mailbox.NewClient(card.Details.Mailbox, keys)
				if err != nil {
					return command.Exit(2, err)
				}
				recipient, err := chain.Diana().Recipient(ctx, card.Details.Recipient, card.Details.Account)
				if err != nil {
					return command.Exit(3, err)
				}
				if err := admission.SendAuditRotation(ctx, relay, card, keys, recipient, epoch, members); err != nil {
					return command.Exit(8, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Audit rotation requested for epoch %d\n", epoch+1)
				return nil
			})
		},
	}
	rotate.Flags().StringVar(&target, "door", "", "Door account or trusted alias")
	rotate.Flags().Uint64Var(&epoch, "epoch", 0, "current epoch (0 for the first membership)")
	rotate.Flags().StringSliceVar(&members, "member", nil, "auditor accounts for the new epoch")
	rotate.Flags().BoolVar(&clearMembers, "clear", false, "remove all auditors")
	audit.AddCommand(rotate)
	return audit
}

func (s *settings) historyCommand() *cobra.Command {
	group := &cobra.Command{Use: "history", Short: "Read verified audit receipts"}
	var target, from string
	group.PersistentFlags().StringVar(&target, "door", "", "Door account or trusted alias")
	group.PersistentFlags().StringVar(&from, "from", "", "import an encrypted receipt export")
	run := func(cmd *cobra.Command, args []string) error {
		var id common.Hash
		if len(args) != 0 && (id.UnmarshalText([]byte(args[0])) != nil || id == (common.Hash{})) {
			return command.Exit(2, errors.New("set a nonzero 32-byte receipt reference in hex"))
		}
		selected, err := s.sessionDoor(target)
		if err != nil {
			return command.Exit(2, err)
		}
		card, pin, trusted, err := s.localDoor(selected)
		if err != nil {
			return err
		}
		verify, cancel := context.WithTimeout(cmd.Context(), 15*time.Second)
		err = verifyStatusCard(verify, card, pin, trusted)
		cancel()
		if err != nil {
			return command.Exit(3, err)
		}
		keys, err := command.Unlock(command.Profile(s.home, s.profile), "Auditor passphrase")
		if err != nil {
			return command.Exit(8, err)
		}
		defer keys.Clear()
		if s.home == "" {
			return command.Exit(8, errors.New("set a local configuration directory"))
		}
		db, err := protocol.OpenState(filepath.Join(s.home, "history", keys.Account.Bech32+".db"))
		if err != nil {
			return command.Exit(8, err)
		}
		defer db.Close()
		var relay *mailbox.Client
		if from != "" {
			f, err := os.Open(from)
			if err != nil {
				return command.Exit(8, err)
			}
			defer f.Close()
			raw, err := io.ReadAll(io.LimitReader(f, protocol.MaxEnvelope+1))
			if err != nil {
				return command.Exit(8, err)
			}
			if err := admission.ImportAuditReceipt(db, card, keys, raw); err != nil {
				return command.Exit(8, err)
			}
		} else {
			relay, err = mailbox.NewClient(card.Details.Mailbox, keys)
			if err != nil {
				return command.Exit(3, err)
			}
		}
		ctx, stop := context.WithTimeout(cmd.Context(), 15*time.Second)
		defer stop()
		receipts, loadErr := admission.LoadHistory(ctx, db, relay, card, keys)
		count := 0
		for _, receipt := range receipts {
			if id == (common.Hash{}) || id == receipt.ID {
				printReceipt(cmd.OutOrStdout(), receipt, id != (common.Hash{}))
				count++
			}
		}
		if loadErr != nil {
			return command.Exit(8, fmt.Errorf("couldn't load all receipt updates: %w", loadErr))
		}
		if count == 0 {
			if id != (common.Hash{}) {
				return command.Exit(8, errors.New("no verified receipt with that reference"))
			}
			fmt.Fprintln(cmd.OutOrStdout(), "No verified receipts")
		}
		return nil
	}
	group.AddCommand(
		&cobra.Command{Use: "list", Short: "List verified receipts", Args: cobra.NoArgs, RunE: run},
		&cobra.Command{Use: "show <receipt-id>", Short: "Inspect a verified receipt", Args: cobra.ExactArgs(1), RunE: run},
	)
	return group
}

func printReceipt(out io.Writer, r admission.AuditReceipt, details bool) {
	utc := func(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }
	fmt.Fprintf(out, "Receipt %s · %s · %s · Epoch %d · Signature verified\n", r.ID.Hex(), utc(r.CleanupObservedAt), r.Cleanup, r.Epoch)
	if !details {
		return
	}
	fmt.Fprintf(out, "Door %s\nSession %s\nRequest %s\nRequester %s\n", r.Door, r.Session.Hex(), r.Request.Hex(), r.Requester)
	if r.Service != "" {
		fmt.Fprintf(out, "Service %s · Purchase %s\n", r.Service, r.Purchase.Hex())
		if r.ConsumptionTx != (common.Hash{}) {
			fmt.Fprintf(out, "Consumption transaction %s\n", r.ConsumptionTx.Hex())
		}
	} else {
		fmt.Fprintf(out, "Role %s · Approved by %s\n", r.Role, r.Approver)
	}
	fmt.Fprintf(out, "Requested duration %s · Termination observed %s · %s\n", time.Duration(r.RequestedSeconds)*time.Second, utc(r.TerminationObservedAt), r.Cause)
	if r.Cleanup == lease.Closed {
		if r.Service != "" {
			fmt.Fprintln(out, "Cleanup verified for firewall access, WireGuard peer and private service")
		} else {
			fmt.Fprintln(out, "Cleanup verified for firewall access, WireGuard peer, SSH authorization and contained workloads")
		}
	}
	if r.ActiveObservedAt == 0 {
		fmt.Fprintln(out, "Connection unobserved")
	} else {
		fmt.Fprintf(out, "Observed connection duration %s\n", time.Duration(r.ActualSeconds)*time.Second)
	}
	if r.RevocationBlock != (common.Hash{}) {
		fmt.Fprintf(out, "Revocation observed in block %s\n", r.RevocationBlock.Hex())
	}
	if r.Corrects != (common.Hash{}) {
		fmt.Fprintf(out, "Corrects receipt %s\n", r.Corrects.Hex())
	}
}
