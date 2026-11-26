package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
)

type sessionDisplay struct {
	Version      uint64                   `json:"version"`
	Session      common.Hash              `json:"sessionId"`
	State        string                   `json:"state"`
	Monitoring   string                   `json:"chainMonitoring"`
	LastVerified *admission.SessionStatus `json:"lastVerified,omitempty"`
}

func (s *settings) sessionsCommand() *cobra.Command {
	var target string
	var asJSON bool
	group := &cobra.Command{Use: "sessions", Short: "Inspect verified Door session status"}
	group.PersistentFlags().StringVar(&target, "door", "", "trusted Door account or alias")
	group.PersistentFlags().BoolVar(&asJSON, "json", false, "write session status as JSON")
	run := func(cmd *cobra.Command, args []string) error {
		var ref common.Hash
		if len(args) == 1 && (ref.UnmarshalText([]byte(args[0])) != nil || ref == (common.Hash{})) {
			return command.Exit(2, errors.New("set a nonzero 32-byte session reference in hex"))
		}
		selected, err := s.sessionDoor(target)
		if err != nil {
			return command.Exit(2, err)
		}
		results, err := s.sessionStatus(cmd.Context(), selected)
		now := time.Now()
		if !asJSON && err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "Session updates unavailable. Showing last verified status if available.")
		}
		slices.SortFunc(results, func(a, b admission.SessionStatus) int { return strings.Compare(a.Session.Hex(), b.Session.Hex()) })
		output := make([]sessionDisplay, 0, len(results))
		for _, record := range results {
			if ref == (common.Hash{}) || record.Session == ref {
				output = append(output, displaySession(now, &record, err != nil))
			}
		}
		if ref != (common.Hash{}) && len(output) == 0 {
			output = append(output, sessionDisplay{Version: 1, Session: ref, State: "Unknown", Monitoring: "Unknown"})
		}
		if asJSON {
			var value any = output
			if ref != (common.Hash{}) {
				value = output[0]
			}
			if writeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(value); writeErr != nil {
				return command.Exit(8, writeErr)
			}
		} else {
			for _, item := range output {
				printSession(cmd.OutOrStdout(), item)
			}
			if len(output) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No verified session status")
			}
		}
		if err != nil {
			return command.Exit(8, err)
		}
		if len(output) == 1 && output[0].State == string(lease.CleanupIncomplete) {
			return command.SilentExit(7)
		}
		return nil
	}
	group.AddCommand(
		&cobra.Command{Use: "list", Short: "List observed sessions", Args: cobra.NoArgs, RunE: run},
		&cobra.Command{Use: "show <session-id>", Short: "Show the last verified session observation", Args: cobra.ExactArgs(1), RunE: run},
	)
	return group
}

func (s *settings) sessionDoor(target string) (string, error) {
	if target != "" {
		return target, nil
	}
	files, err := os.ReadDir(s.cardsDirectory())
	if err != nil {
		return "", err
	}
	var selected string
	for _, file := range files {
		account, ok := strings.CutSuffix(file.Name(), ".card")
		if !ok || file.IsDir() {
			continue
		}
		if selected != "" {
			return "", errors.New("use --door to select a Door")
		}
		selected = account
	}
	if selected == "" {
		return "", errors.New("use --door with a configured Door")
	}
	return selected, nil
}

func (s *settings) sessionStatus(ctx context.Context, target string) ([]admission.SessionStatus, error) {
	keys, err := command.Unlock(command.Profile(s.home, s.profile), "Identity passphrase")
	if err != nil {
		return nil, err
	}
	defer keys.Clear()
	return s.loadSessionStatus(ctx, target, keys)
}

func (s *settings) loadSessionStatus(ctx context.Context, target string, keys *identity.Keys) ([]admission.SessionStatus, error) {
	card, pin, trusted, err := s.localDoor(target)
	if err != nil {
		return nil, err
	}
	verify, cancelVerify := context.WithTimeout(ctx, 12*time.Second)
	verification := verifyStatusCard(verify, card, pin, trusted)
	cancelVerify()
	return s.readSessionEvidence(ctx, card, keys, verification)
}

func (s *settings) readSessionEvidence(ctx context.Context, card door.Card, keys *identity.Keys, verification error) ([]admission.SessionStatus, error) {
	var relay *mailbox.Client
	if verification == nil {
		relay, verification = mailbox.NewClient(card.Details.Mailbox, keys)
	}
	db, err := protocol.OpenState(sessionCachePath(s.home, keys))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	call, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	status, err := admission.LoadSessionStatus(call, db, relay, card, keys)
	return status, errors.Join(verification, err)
}

func verifyStatusCard(ctx context.Context, card door.Card, pin chain.Registry, trusted bool) error {
	native := chain.Diana()
	if trusted {
		signing, err := native.SigningKey(ctx, card.Details.Account)
		if err != nil {
			return err
		}
		return card.VerifySigner(signing)
	}
	evm, err := chain.Connect(ctx, native)
	if err != nil {
		return err
	}
	defer evm.Close()
	return card.Verify(ctx, native, evm, pin, card.Details.Account)
}

func sessionCachePath(home string, keys *identity.Keys) string {
	return filepath.Join(home, "sessions", keys.Account.Bech32+".db")
}

func displaySession(now time.Time, record *admission.SessionStatus, unavailable bool) sessionDisplay {
	value := sessionDisplay{Version: 1, Session: record.Session, State: string(record.State), LastVerified: record, Monitoring: "Available"}
	if (unavailable || !record.Fresh(now)) && record.State != lease.Closed {
		value.State = "Unknown"
	}
	if record.MonitoringDegraded(now) {
		value.Monitoring = "Unknown"
		if record.Degraded && record.Fresh(now) {
			value.Monitoring = "Degraded"
		}
	}
	if unavailable {
		value.Monitoring = "Unknown"
	}
	return value
}

func printSession(out io.Writer, item sessionDisplay) {
	fmt.Fprintf(out, "Session %s · %s\n", item.Session.Hex(), item.State)
	if record := item.LastVerified; record != nil {
		utc := func(unix int64) string { return time.Unix(unix, 0).UTC().Format(time.RFC3339) }
		scope := record.Role
		if record.Service != "" {
			scope = record.Service
		}
		fmt.Fprintf(out, "%s · Expires %s · Last verified %s\nRequest %s\n", scope, utc(record.Deadline), utc(record.Observed), record.RequestID.Hex())
		if item.State == "Unknown" {
			fmt.Fprintf(out, "Last known state %s · Closure unknown\n", record.State)
		}
		if record.RevokedAt != 0 {
			fmt.Fprintf(out, "Revocation observed %s · Block %s\n", utc(record.RevokedAt), record.RevokedBlock.Hex())
		}
		if record.ClosedAt != 0 {
			if record.Cause == "Revoked" {
				fmt.Fprintf(out, "Revocation enforced %s\n", utc(record.ClosedAt))
			} else {
				fmt.Fprintf(out, "Closure verified %s\n", utc(record.ClosedAt))
			}
		}
		if record.ReceiptState != "" {
			fmt.Fprintf(out, "Receipt %s\n", strings.ToLower(record.ReceiptState))
		}
	}
	fmt.Fprintf(out, "Chain monitoring %s\n", strings.ToLower(item.Monitoring))
}
