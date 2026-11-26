package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"knock/internal/admission"
	"knock/internal/chain"
	"knock/internal/command"
	"knock/internal/door"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/term"
)

type paymentRecord struct {
	Registry    chain.Registry
	Door        common.Hash
	Buyer       common.Address
	Offer       chain.Offer
	Session     common.Hash
	RedeemBy    uint64
	Transaction common.Hash
	Connected   bool
	Unfulfilled bool
}

var errPaidProvisioning = errors.New("couldn't prepare private service access")

func formatQOR(uqor uint64) string {
	return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%d.%06d", uqor/1_000_000, uqor%1_000_000), "0"), ".")
}

func (s *settings) buyPass(cmd *cobra.Command, target string, duration time.Duration, price uint64) error {
	command.Wait(cmd.ErrOrStderr(), "Resolving Door…")
	return s.withDoor(cmd, target, func(ctx context.Context, evm *chain.EVM, card door.Card) error {
		d := card.Details
		if d.Mode != door.Metered || !d.Policy.Enabled || uint64(duration/time.Second) != d.Policy.MaxDurationSeconds {
			return command.Exit(2, errors.New("choose the advertised fixed duration of an enabled Metered Door"))
		}
		if s.home == "" {
			return command.Exit(2, errors.New("set a local Knock profile directory for payment records"))
		}
		if s.mailbox != "" && s.mailbox != d.Mailbox {
			return command.Exit(3, errors.New("the Mailbox origin differs from the signed Door Card"))
		}
		terms, err := d.Policy.PaymentOffer()
		if err != nil {
			return command.Exit(3, err)
		}
		if _, err := protocol.Origin(d.Mailbox); err != nil {
			return command.Exit(2, err)
		}
		out := cmd.ErrOrStderr()
		command.OK(out, "Door identity verified")
		offer := d.Policy.Offer
		command.Field(out, "Door", d.Account)
		command.Field(out, "Service", offer.Service)
		command.Field(out, "Duration", duration.String())
		command.Field(out, "Price", formatQOR(offer.PriceUQOR)+" test QOR on Diana (network fees additional)")
		switch {
		case cmd.Flags().Changed("price-uqor"):
			if price != offer.PriceUQOR {
				return command.Exit(5, errors.New("the offered price differs from --price-uqor"))
			}
		case !term.IsTerminal(int(os.Stdin.Fd())):
			return command.Exit(2, errors.New("confirm the payment in a terminal or supply the exact --price-uqor"))
		default:
			fmt.Fprint(out, "Purchase one pass? [y/N] ")
			line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
			if err != nil || !strings.EqualFold(strings.TrimSpace(line), "y") {
				fmt.Fprintln(out, "Purchase cancelled.")
				return nil
			}
		}
		keys, err := command.Unlock(command.Profile(s.home, s.profile), "Identity passphrase")
		if err != nil {
			return command.Exit(8, err)
		}
		defer keys.Clear()
		relay, err := mailbox.NewClient(d.Mailbox, keys)
		if err != nil {
			return command.Exit(2, err)
		}
		authority := admission.Diana{Native: chain.Diana(), EVM: evm, Registry: d.Registry, Cards: s.cardsDirectory(), Origin: d.Mailbox}
		request, messages, err := admission.BuildRequest(ctx, authority, relay, keys, card, "", duration, "")
		if err != nil {
			return command.Exit(3, err)
		}
		defer request.Clear()
		for _, message := range messages {
			if err := relay.Send(ctx, message); err != nil {
				if err := relay.Send(ctx, message); err != nil {
					return command.Exit(8, errors.New("couldn't submit the private service request"))
				}
			}
		}
		commitment := request.Commitment()
		record := paymentRecord{Registry: d.Registry, Door: d.DoorID, Buyer: common.BytesToAddress(keys.Account.Bytes),
			Offer: terms, Session: admission.SessionReference(d.DoorID, request.ID()), RedeemBy: uint64(request.Deadline().Unix())}
		call, cancel := context.WithDeadline(cmd.Context(), request.Deadline())
		defer cancel()
		_, buyErr := evm.Buy(call, d.Registry, d.DoorID, commitment, terms, record.RedeemBy, keys,
			func(message string) { fmt.Fprintln(out, message) }, func(hash common.Hash) error {
				saved := record
				saved.Transaction = hash
				if err := s.storePayment(commitment, saved); err != nil {
					return err
				}
				record = saved
				fmt.Fprintf(out, "Submitting payment %s · Pass %s\n", hash.Hex(), commitment.Hex())
				return nil
			})
		pass, err := evm.Payment(call, d.Registry, commitment)
		confirmed := err == nil && record.matches(pass)
		if !confirmed {
			if record.Transaction == (common.Hash{}) {
				return command.Exit(5, errors.Join(buyErr, err, errors.New("payment was not submitted")))
			}
			state, receiptErr := evm.PaymentReceipt(call, record.Transaction)
			if receiptErr == nil && state == chain.TransactionReverted {
				return command.Exit(5, fmt.Errorf("payment %s reverted", record.Transaction.Hex()))
			}
			message := "Payment outcome unavailable"
			if receiptErr == nil && state == chain.TransactionPending {
				message = "Payment pending"
			}
			return command.Exit(5, fmt.Errorf("%s · Transaction %s · Run knock payment show %s before paying again",
				message, record.Transaction.Hex(), commitment.Hex()))
		}
		command.OK(out, "Payment confirmed · Transaction "+record.Transaction.Hex())
		command.Field(out, "Session", record.Session.Hex())
		command.Wait(out, "Waiting for access…")
		connected := false
		if err := waitForDecision(cmd, authority, relay, request, func() {
			connected, record.Connected = true, true
			if err := s.storePayment(commitment, record); err != nil {
				fmt.Fprintln(out, "Couldn't save the verified connection in the payment record.")
			}
		}); err != nil {
			if !connected {
				state := "Service access unverified"
				if errors.Is(err, errPaidProvisioning) {
					state = "Pass unfulfilled"
					record.Unfulfilled = true
					if err := s.storePayment(commitment, record); err != nil {
						fmt.Fprintln(out, "Couldn't save the Door's failure notice in the payment record.")
					}
				}
				fmt.Fprintf(out, "Payment confirmed. %s. Run knock payment show %s and contact the Door operator before paying again.\n",
					state, commitment.Hex())
			}
			return err
		}
		return nil
	})
}

var paymentBucket = []byte("payments-v1")

func (s *settings) storePayment(commitment common.Hash, record paymentRecord) error {
	db, err := protocol.OpenState(filepath.Join(s.home, "payments.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	return db.Update(func(tx *bolt.Tx) error {
		bucket, err := tx.CreateBucketIfNotExists(paymentBucket)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(record)
		if err != nil {
			return err
		}
		return bucket.Put(commitment[:], raw)
	})
}

func (s *settings) readPayment(commitment common.Hash) (paymentRecord, error) {
	var record paymentRecord
	if s.home == "" {
		return record, errors.New("set a local Knock profile directory")
	}
	path := filepath.Join(s.home, "payments.db")
	if _, err := os.Stat(path); err != nil {
		return record, err
	}
	db, err := protocol.OpenState(path)
	if err != nil {
		return record, err
	}
	defer db.Close()
	err = db.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(paymentBucket)
		if bucket == nil || bucket.Get(commitment[:]) == nil {
			return errors.New("purchase reference was not found in local payment records")
		}
		return json.Unmarshal(bucket.Get(commitment[:]), &record)
	})
	return record, err
}

func (r paymentRecord) matches(pass chain.Purchase) bool {
	return pass.Buyer == r.Buyer && pass.DoorId == r.Door && pass.Offer.Matches(r.Offer) && pass.RedeemBy == r.RedeemBy
}

type paymentDisplay struct {
	Version         int          `json:"version"`
	Pass            common.Hash  `json:"pass"`
	Transaction     common.Hash  `json:"transaction"`
	State           string       `json:"state"`
	ConsumedSession *common.Hash `json:"consumedSession,omitempty"`
	Service         string       `json:"serviceAccess"`
}

func (s *settings) paymentCommand() *cobra.Command {
	group := &cobra.Command{Use: "payment", Short: "Inspect Diana payments"}
	var asJSON bool
	show := &cobra.Command{
		Use: "show <pass>", Short: "Verify the outcome of a service pass payment", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var commitment common.Hash
			if err := commitment.UnmarshalText([]byte(args[0])); err != nil || commitment == (common.Hash{}) {
				return command.Exit(2, errors.New("enter the payment pass reference in hex"))
			}
			record, err := s.readPayment(commitment)
			if err != nil {
				return command.Exit(8, err)
			}
			result := paymentDisplay{Version: 1, Pass: commitment, Transaction: record.Transaction, State: "Unverified", Service: "Unverified"}
			out := cmd.OutOrStdout()
			ctx, cancel := context.WithTimeout(cmd.Context(), 20*time.Second)
			defer cancel()
			lookupErr := verifyPaymentDisplay(ctx, record, &result)
			if asJSON {
				if err := json.NewEncoder(out).Encode(result); err != nil {
					return command.Exit(8, err)
				}
			} else {
				printPaymentDisplay(out, result)
			}
			if lookupErr != nil {
				return command.Exit(5, lookupErr)
			}
			if result.State != "Confirmed" {
				return command.SilentExit(5)
			}
			return nil
		},
	}
	show.Flags().BoolVar(&asJSON, "json", false, "write payment status as JSON")
	group.AddCommand(show)
	return group
}

func verifyPaymentDisplay(ctx context.Context, record paymentRecord, result *paymentDisplay) error {
	evm, err := chain.Connect(ctx, chain.Diana())
	if err != nil {
		return err
	}
	defer evm.Close()
	pass, err := evm.Payment(ctx, record.Registry, result.Pass)
	if err != nil {
		return err
	}
	if !record.matches(pass) {
		state, err := evm.PaymentReceipt(ctx, record.Transaction)
		if err != nil {
			return err
		}
		switch state {
		case chain.TransactionReverted:
			result.State = "Reverted"
		case chain.TransactionPending:
			result.State = "Pending"
		}
		return nil
	}
	result.State = "Confirmed"
	if pass.SessionRef == record.Session {
		result.ConsumedSession = &pass.SessionRef
	}
	switch {
	case record.Connected && result.ConsumedSession != nil:
		result.Service = "Verified"
	case record.Unfulfilled:
		result.Service = "Unfulfilled"
	}
	return nil
}

func printPaymentDisplay(out io.Writer, result paymentDisplay) {
	command.Field(out, "Network", "Diana")
	command.Field(out, "Pass", result.Pass.Hex())
	command.Field(out, "Transaction", result.Transaction.Hex())
	switch result.State {
	case "Reverted":
		command.Field(out, "Payment", "Reverted")
	case "Pending":
		command.Field(out, "Payment", "Pending (check this reference before paying again)")
	case "Confirmed":
		command.Field(out, "Payment", "Confirmed")
		if result.ConsumedSession != nil {
			command.Field(out, "Consumed session", result.ConsumedSession.Hex())
		}
		switch result.Service {
		case "Verified":
			command.Field(out, "Service access", "Verified")
		case "Unfulfilled":
			command.Field(out, "Service access", "Unfulfilled (contact the Door operator with this reference before paying again)")
		default:
			command.Field(out, "Service access", "Unverified (contact the Door operator with this reference before paying again)")
		}
	default:
		command.Field(out, "Payment", "Unverified (check this reference before paying again)")
	}
}
