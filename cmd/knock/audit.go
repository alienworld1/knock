package main

import (
	"context"
	"encoding/json"
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
	"knock/internal/identity"
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
			keys, err := command.Unlock(command.Profile(s.home, s.profile), "Owner passphrase")
			if err != nil {
				return command.Exit(8, err)
			}
			defer keys.Clear()
			if err := s.rotateAudit(cmd.Context(), target, keys, epoch, members); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Audit rotation requested for epoch %d\n", epoch+1)
			return nil
		},
	}
	rotate.Flags().StringVar(&target, "door", "", "Door account or trusted alias")
	rotate.Flags().Uint64Var(&epoch, "epoch", 0, "current epoch (0 for the first membership)")
	rotate.Flags().StringSliceVar(&members, "member", nil, "auditor accounts for the new epoch")
	rotate.Flags().BoolVar(&clearMembers, "clear", false, "remove all auditors")
	audit.AddCommand(rotate)
	return audit
}

func (s *settings) rotateAudit(ctx context.Context, target string, keys *identity.Keys, epoch uint64, members []string) error {
	return s.withVerifiedDoor(ctx, target, func(ctx context.Context, _ *chain.EVM, card door.Card) error {
		d := card.Details
		if d.Owner != keys.Account.Bech32 {
			return command.Exit(3, errOperatorUnauthorized)
		}
		if !d.Policy.Enabled {
			return command.Exit(3, errors.New("the Door policy is disabled"))
		}
		relay, err := mailbox.NewClient(d.Mailbox, keys)
		if err != nil {
			return command.Exit(2, err)
		}
		recipient, err := chain.Diana().Recipient(ctx, d.Recipient, d.Account)
		if err != nil {
			return command.Exit(3, err)
		}
		return command.Exit(8, admission.SendAuditRotation(ctx, relay, card, keys, recipient, epoch, members))
	})
}

func (s *settings) historyCommand() *cobra.Command {
	group := &cobra.Command{Use: "history", Short: "Read verified audit receipts"}
	var target, from string
	var asJSON bool
	group.PersistentFlags().StringVar(&target, "door", "", "Door account or trusted alias")
	group.PersistentFlags().StringVar(&from, "from", "", "import an encrypted receipt export")
	group.PersistentFlags().BoolVar(&asJSON, "json", false, "write verified receipts as JSON")
	run := func(cmd *cobra.Command, args []string) error {
		var id common.Hash
		if len(args) != 0 && (id.UnmarshalText([]byte(args[0])) != nil || id == (common.Hash{})) {
			return command.Exit(2, errors.New("set a nonzero 32-byte receipt reference in hex"))
		}
		selected, err := s.sessionDoor(target)
		if err != nil {
			return command.Exit(2, err)
		}
		keys, err := command.Unlock(command.Profile(s.home, s.profile), "Auditor passphrase")
		if err != nil {
			return command.Exit(8, err)
		}
		defer keys.Clear()
		receipts, loadErr := s.loadHistory(cmd.Context(), selected, from, keys)
		if loadErr != nil && receipts == nil {
			return loadErr
		}
		matches := make([]admission.AuditReceipt, 0, len(receipts))
		for _, receipt := range receipts {
			if id == (common.Hash{}) || id == receipt.ID {
				matches = append(matches, receipt)
			}
		}
		if asJSON {
			if err := json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Version  int                      `json:"version"`
				Receipts []admission.AuditReceipt `json:"receipts"`
			}{1, matches}); err != nil {
				return command.Exit(8, err)
			}
		} else {
			for _, receipt := range matches {
				printReceipt(cmd.OutOrStdout(), receipt, id != (common.Hash{}))
			}
		}
		if loadErr != nil {
			return loadErr
		}
		if len(matches) == 0 {
			if id != (common.Hash{}) {
				return command.Exit(8, errors.New("no verified receipt with that reference"))
			}
			if !asJSON {
				fmt.Fprintln(cmd.OutOrStdout(), "No verified receipts")
			}
		}
		return nil
	}
	group.AddCommand(
		&cobra.Command{Use: "list", Short: "List verified receipts", Args: cobra.NoArgs, RunE: run},
		&cobra.Command{Use: "show <receipt-id>", Short: "Inspect a verified receipt", Args: cobra.ExactArgs(1), RunE: run},
	)
	return group
}

func (s *settings) loadHistory(ctx context.Context, selected, from string, keys *identity.Keys) ([]admission.AuditReceipt, error) {
	card, pin, trusted, err := s.localDoor(selected)
	if err != nil {
		return nil, err
	}
	verify, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = verifyStatusCard(verify, card, pin, trusted)
	cancel()
	if err != nil {
		return nil, command.Exit(3, err)
	}
	if s.home == "" {
		return nil, command.Exit(8, errors.New("set a local configuration directory"))
	}
	db, err := protocol.OpenState(filepath.Join(s.home, "history", keys.Account.Bech32+".db"))
	if err != nil {
		return nil, command.Exit(8, err)
	}
	defer db.Close()
	var relay *mailbox.Client
	if from != "" {
		f, err := os.Open(from)
		if err != nil {
			return nil, command.Exit(8, err)
		}
		defer f.Close()
		raw, err := io.ReadAll(io.LimitReader(f, protocol.MaxEnvelope+1))
		if err != nil {
			return nil, command.Exit(8, err)
		}
		if err := admission.ImportAuditReceipt(db, card, keys, raw); err != nil {
			return nil, command.Exit(8, err)
		}
	} else {
		relay, err = mailbox.NewClient(card.Details.Mailbox, keys)
		if err != nil {
			return nil, command.Exit(3, err)
		}
	}
	call, stop := context.WithTimeout(ctx, 15*time.Second)
	defer stop()
	receipts, err := admission.LoadHistory(call, db, relay, card, keys)
	if err != nil {
		return receipts, command.Exit(8, fmt.Errorf("couldn't load all receipt updates: %w", err))
	}
	return receipts, nil
}

func printReceipt(out io.Writer, r admission.AuditReceipt, details bool) {
	utc := func(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }
	if !details {
		fmt.Fprintf(out, "Receipt %s · %s · %s · Epoch %d · Signature verified\n", r.ID.Hex(), utc(r.CleanupObservedAt), r.Cleanup, r.Epoch)
		return
	}
	command.Field(out, "Receipt", r.ID.Hex())
	command.Field(out, "Cleanup", string(r.Cleanup))
	command.Field(out, "Cleanup observed", utc(r.CleanupObservedAt))
	command.Field(out, "Epoch", fmt.Sprintf("%d", r.Epoch))
	command.Field(out, "Signature", "ML-DSA-87 + secp256k1 verified")
	command.Field(out, "Door", r.Door)
	command.Field(out, "Session", r.Session.Hex())
	command.Field(out, "Request", r.Request.Hex())
	command.Field(out, "Requester", r.Requester)
	if r.Service != "" {
		command.Field(out, "Service", r.Service)
		command.Field(out, "Purchase", r.Purchase.Hex())
		if r.ConsumptionTx != (common.Hash{}) {
			command.Field(out, "Consumption tx", r.ConsumptionTx.Hex())
		}
	} else {
		command.Field(out, "Role", r.Role)
		command.Field(out, "Approver", r.Approver)
	}
	command.Field(out, "Requested", (time.Duration(r.RequestedSeconds) * time.Second).String())
	command.Field(out, "Termination", fmt.Sprintf("%s (%s)", utc(r.TerminationObservedAt), r.Cause))
	if r.Cleanup == lease.Closed {
		if r.Service != "" {
			command.Field(out, "Verified cleanup", "Firewall access, WireGuard peer, private service")
		} else {
			command.Field(out, "Verified cleanup", "Firewall access, WireGuard peer, SSH authorization, contained workloads")
		}
	}
	if r.ActiveObservedAt == 0 {
		command.Field(out, "Connection", "Unobserved")
	} else {
		command.Field(out, "Connection", (time.Duration(r.ActualSeconds)*time.Second).String()+" observed")
	}
	if r.RevocationBlock != (common.Hash{}) {
		command.Field(out, "Revocation block", r.RevocationBlock.Hex())
	}
	if r.Corrects != (common.Hash{}) {
		command.Field(out, "Corrects receipt", r.Corrects.Hex())
	}
}
