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
	"knock/internal/identity"
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

func (s *settings) requestFlags(root *cobra.Command) {
	var ssh, tunnel bool
	var role, reason string
	var duration, pay time.Duration
	var price uint64
	root.Use = "knock <door> [--ssh --role <role> --for <duration> --reason <reason> | --tunnel --pay <duration>]"
	root.Args = cobra.MaximumNArgs(1)
	root.Flags().BoolVar(&ssh, "ssh", false, "request SSH access")
	root.Flags().StringVar(&role, "role", "", "role advertised by the Door")
	root.Flags().DurationVar(&duration, "for", 0, "requested access duration")
	root.Flags().StringVar(&reason, "reason", "", "reason for approvers; use - to enter privately")
	root.Flags().BoolVar(&tunnel, "tunnel", false, "connect to a metered private service")
	root.Flags().DurationVar(&pay, "pay", 0, "duration of the advertised pass")
	root.Flags().Uint64Var(&price, "price-uqor", 0, "confirm payment only at this exact price in uqor")
	root.RunE = func(cmd *cobra.Command, args []string) error {
		if cmd.Flags().Changed("tunnel") || cmd.Flags().Changed("pay") || cmd.Flags().Changed("price-uqor") {
			if len(args) != 1 || !tunnel || pay <= 0 || pay%time.Second != 0 ||
				cmd.Flags().Changed("ssh") || cmd.Flags().Changed("role") || cmd.Flags().Changed("for") || cmd.Flags().Changed("reason") {
				return command.Exit(2, errors.New("set a Door, --tunnel, and --pay in whole seconds"))
			}
			return s.buyPass(cmd, args[0], pay, price)
		}
		if len(args) == 0 && !cmd.Flags().Changed("ssh") && !cmd.Flags().Changed("role") &&
			!cmd.Flags().Changed("for") && !cmd.Flags().Changed("reason") {
			return cmd.Help()
		}
		if len(args) != 1 || !ssh || (role != "logs" && role != "maintenance") ||
			duration <= 0 || duration%time.Second != 0 || (reason != "-" && !admission.ValidReason(reason)) {
			return command.Exit(2, errors.New("set a Door, --ssh, --role, --for in whole seconds, and --reason"))
		}
		if reason == "-" {
			if !term.IsTerminal(int(os.Stdin.Fd())) {
				return command.Exit(2, errors.New("enter the private reason from a terminal"))
			}
			value, err := command.Prompt("Reason for approvers")
			if err != nil {
				return command.Exit(2, err)
			}
			reason = string(value)
			clear(value)
			if !admission.ValidReason(reason) {
				return command.Exit(2, fmt.Errorf("enter a printable reason of up to %d bytes", admission.MaxReason))
			}
		}
		command.Wait(cmd.ErrOrStderr(), "Resolving "+args[0]+"…")
		return s.withDoor(cmd, args[0], func(ctx context.Context, evm *chain.EVM, card door.Card) error {
			if s.mailbox != "" && s.mailbox != card.Details.Mailbox {
				return command.Exit(3, errors.New("the Mailbox origin differs from the signed Door Card"))
			}
			if _, err := protocol.Origin(card.Details.Mailbox); err != nil {
				return command.Exit(2, errors.New("the Door Card has no valid Mailbox origin. Ask the Door operator for a current Card."))
			}
			if card.Details.Mode != door.Approval || !card.Details.Policy.Enabled ||
				uint64(duration/time.Second) > card.Details.Policy.MaxDurationSeconds {
				return command.Exit(2, errors.New("choose a duration within the enabled Door policy"))
			}
			command.OK(cmd.ErrOrStderr(), "Door identity verified")
			keys, err := command.Unlock(command.Profile(s.home, s.profile), "Identity passphrase")
			if err != nil {
				return command.Exit(8, err)
			}
			defer keys.Clear()
			relay, err := mailbox.NewClient(card.Details.Mailbox, keys)
			if err != nil {
				return command.Exit(2, err)
			}
			authority := admission.Diana{Native: chain.Diana(), EVM: evm, Registry: card.Details.Registry,
				Cards: s.cardsDirectory(), Origin: card.Details.Mailbox}
			request, messages, err := admission.BuildRequest(ctx, authority, relay, keys, card, role, duration, reason)
			if err != nil {
				return command.Exit(3, err)
			}
			defer request.Clear()
			for _, message := range messages {
				// Retry the exact delivery bytes if its response was lost.
				if err := relay.Send(ctx, message); err != nil {
					if err := relay.Send(ctx, message); err != nil {
						return command.Exit(8, fmt.Errorf("couldn't submit all request deliveries. Request %s may be incomplete.", request.ID().Hex()))
					}
				}
			}
			errOut := cmd.ErrOrStderr()
			command.OK(errOut, "Request sealed and sent")
			command.Field(errOut, "Door", card.Details.Account)
			command.Field(errOut, "Role", role)
			command.Field(errOut, "Duration", duration.String())
			command.Field(errOut, "Request", request.ID().Hex())
			command.Field(errOut, "Decide by", request.Deadline().UTC().Format("15:04:05")+" UTC")
			command.Wait(errOut, "Waiting for approval…")
			return waitForDecision(cmd, authority, relay, request, nil)
		})
	}
}

func waitForDecision(cmd *cobra.Command, authority admission.Authority, relay *mailbox.Client, request *admission.Request, connected func()) error {
	ctx, cancel := context.WithDeadline(cmd.Context(), request.Deadline())
	defer cancel()
	waitingFor, statusUnavailable, outcomeUnavailable := "approval", "Approval status unavailable. Retrying.", "Couldn't verify an approval outcome."
	if request.Metered() {
		waitingFor, statusUnavailable, outcomeUnavailable = "access", "Access status unavailable. Retrying.", "Couldn't verify an access outcome."
	}
	failures := 0
	for {
		messages, err := relay.Inbox(ctx)
		transportError := err != nil
		verificationError := false
		for _, message := range messages {
			if message.ID != request.StatusID() && message.ID != request.ConnectionID() {
				continue
			}
			response, err := request.ReadResponse(ctx, authority, message)
			switch {
			case errors.Is(err, admission.ErrInvalid):
				continue
			case errors.Is(err, admission.ErrExpired):
				return command.Exit(4, admission.ErrExpired)
			case err != nil:
				verificationError = true
				continue
			}
			// The signed outcome remains valid if the acknowledgment is lost.
			ackCtx, stop := context.WithTimeout(ctx, time.Second)
			_ = relay.Ack(ackCtx, message.ID)
			stop()
			switch response.Outcome {
			case admission.Denied:
				return command.Exit(4, errors.New("Request denied"))
			case admission.ProvisionFailed:
				if request.Metered() {
					return command.Exit(6, errPaidProvisioning)
				}
				return command.Exit(6, errors.New("Couldn't prepare SSH access. Contact the Door operator."))
			case admission.Ready:
				defer clear(response.Connection.PSK[:])
				errOut := cmd.ErrOrStderr()
				command.OK(errOut, fmt.Sprintf("Access granted · Expires %s UTC", response.Deadline.UTC().Format("15:04:05")))
				command.Wait(errOut, "Connecting…")
				err := request.Connect(cmd.Context(), response, lease.Streams{
					In: cmd.InOrStdin(), Out: cmd.OutOrStdout(), Err: errOut, OnConnected: connected,
				})
				if err == nil && !request.Metered() {
					command.Info(errOut, "Connection closed.")
				}
				return sshExit(err, errOut)
			default:
				fmt.Fprintln(cmd.OutOrStdout(), "Authorized")
				return nil
			}
		}
		failed := transportError || verificationError
		if ctx.Err() != nil {
			failed = failures != 0
		}
		if failed && failures == 0 && ctx.Err() == nil {
			fmt.Fprintln(cmd.ErrOrStderr(), statusUnavailable)
		}
		if failed {
			failures = min(failures+1, 3)
		} else {
			failures = 0
		}
		timer := time.NewTimer(mailbox.PollDelay(failures))
		select {
		case <-ctx.Done():
			timer.Stop()
			if cmd.Context().Err() != nil {
				return command.Exit(8, fmt.Errorf("Stopped waiting for %s", waitingFor))
			}
			if failures != 0 {
				return command.Exit(8, fmt.Errorf("Request deadline passed. %s", outcomeUnavailable))
			}
			return command.Exit(4, admission.ErrExpired)
		case <-timer.C:
		}
	}
}

func (s *settings) publishRecipientCommand() *cobra.Command {
	return &cobra.Command{
		Use: "publish", Short: "Publish your registered recipient card to the Mailbox", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := protocol.Origin(s.mailbox); err != nil {
				return command.Exit(2, err)
			}
			keys, err := command.Unlock(command.Profile(s.home, s.profile), "Identity passphrase")
			if err != nil {
				return command.Exit(8, err)
			}
			defer keys.Clear()
			card, err := admission.RecipientCard(keys)
			if err != nil {
				return command.Exit(3, err)
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			if _, err := chain.Diana().Recipient(ctx, card, keys.Account.Bech32); err != nil {
				return command.Exit(3, err)
			}
			relay, err := mailbox.NewClient(s.mailbox, keys)
			if err != nil {
				return command.Exit(2, err)
			}
			if err := relay.Publish(ctx, card); err != nil {
				return command.Exit(8, err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Recipient card published")
			return nil
		},
	}
}

func (s *settings) requestsCommand() *cobra.Command {
	requests := &cobra.Command{Use: "requests", Short: "Review requests addressed to your identity"}
	for _, mode := range []string{"list", "show"} {
		var asJSON bool
		use, short, args := mode, "List verified requests", cobra.NoArgs
		if mode == "show" {
			use, short, args = "show <request-id>", "Show a verified request and its reason", cobra.ExactArgs(1)
		}
		cmd := &cobra.Command{
			Use: use, Short: short, Args: args,
			RunE: func(cmd *cobra.Command, args []string) error {
				target, err := requestTarget(args)
				if err != nil {
					return command.Exit(2, err)
				}
				return s.withReviews(cmd, target, func(_ context.Context, _ admission.Diana, _ *mailbox.Client, _ *identity.Keys, reviews []admission.Review) error {
					summaries := make([]admission.ReviewSummary, 0, len(reviews))
					for _, review := range reviews {
						summaries = append(summaries, review.Summary())
					}
					if asJSON {
						return command.Exit(8, json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
							Version  int                       `json:"version"`
							Requests []admission.ReviewSummary `json:"requests"`
						}{1, summaries}))
					}
					if target != (common.Hash{}) {
						printReview(cmd.OutOrStdout(), reviews[0])
					} else if len(reviews) == 0 {
						fmt.Fprintln(cmd.OutOrStdout(), "No requests")
					} else {
						for _, r := range summaries {
							fmt.Fprintf(cmd.OutOrStdout(), "%s  %s  %-11s  %-6s  until %s UTC\n", r.ID.Hex(), r.Requester, r.Role,
								time.Duration(r.Seconds)*time.Second, r.Deadline.UTC().Format("15:04:05"))
						}
					}
					return nil
				})
			},
		}
		cmd.Flags().BoolVar(&asJSON, "json", false, "write verified request details without the reason")
		requests.AddCommand(cmd)
	}
	return requests
}

func (s *settings) decisionCommand(verb string, outcome admission.Outcome) *cobra.Command {
	var yes bool
	short := "Approve a verified request as reviewed"
	if verb == "deny" {
		short = "Deny a verified request as reviewed"
	}
	cmd := &cobra.Command{
		Use: verb + " <request-id>", Short: short, Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := requestTarget(args)
			if err != nil {
				return command.Exit(2, err)
			}
			if !yes && !term.IsTerminal(int(os.Stdin.Fd())) {
				return command.Exit(2, errors.New("confirm from a terminal or pass --yes with the exact reviewed request ID"))
			}
			return s.withReviews(cmd, target, func(ctx context.Context, authority admission.Diana, relay *mailbox.Client, keys *identity.Keys, reviews []admission.Review) error {
				review := reviews[0]
				if !yes {
					printReview(cmd.ErrOrStderr(), review)
					fmt.Fprintf(cmd.ErrOrStderr(), "Type yes to %s this request: ", verb)
					answer, err := bufio.NewReader(io.LimitReader(cmd.InOrStdin(), 64)).ReadString('\n')
					if err != nil || strings.TrimSpace(answer) != "yes" {
						return command.Exit(2, errors.New("Decision canceled"))
					}
				}
				if err := s.sendDecision(ctx, authority, relay, keys, review, outcome); err != nil {
					return err
				}
				fmt.Fprintln(cmd.OutOrStdout(), "Decision sent. Waiting for the Door to verify it.")
				return nil
			})
		},
	}
	cmd.Flags().BoolVar(&yes, "yes", false, "confirm the exact request already reviewed")
	return cmd
}

func requestTarget(args []string) (common.Hash, error) {
	var id common.Hash
	if len(args) > 0 && (id.UnmarshalText([]byte(args[0])) != nil || id == (common.Hash{})) {
		return id, errors.New("expected a nonzero 32-byte request ID in hex")
	}
	return id, nil
}

func printReview(out io.Writer, review admission.Review) {
	r := review.Summary()
	command.Field(out, "Verified request", r.ID.Hex())
	command.Field(out, "Door", r.Door)
	command.Field(out, "Requester", r.Requester)
	command.Field(out, "Service", r.Service)
	command.Field(out, "Role", r.Role)
	command.Field(out, "Duration", (time.Duration(r.Seconds) * time.Second).String())
	command.Field(out, "Reason", review.Reason())
	command.Field(out, "Deadline", r.Deadline.UTC().Format(time.RFC3339))
}

func (s *settings) withReviews(cmd *cobra.Command, target common.Hash, use func(context.Context, admission.Diana, *mailbox.Client, *identity.Keys, []admission.Review) error) error {
	keys, err := command.Unlock(command.Profile(s.home, s.profile), "Identity passphrase")
	if err != nil {
		return command.Exit(8, err)
	}
	defer keys.Clear()
	return s.loadReviews(cmd.Context(), target, keys, use)
}

func (s *settings) operatorState(keys *identity.Keys) string {
	profile := command.Profile(s.home, s.profile)
	return filepath.Join(filepath.Dir(profile), "admission", keys.Account.Bech32, "operator.db")
}

func (s *settings) sendDecision(ctx context.Context, authority admission.Diana, relay *mailbox.Client, keys *identity.Keys, review admission.Review, outcome admission.Outcome) error {
	db, err := protocol.OpenState(s.operatorState(keys))
	if err != nil {
		return command.Exit(8, err)
	}
	defer db.Close()
	call, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	if err := admission.SendDecision(call, db, authority, relay, keys, review, outcome); err != nil {
		if errors.Is(err, admission.ErrExpired) {
			return command.Exit(4, err)
		}
		if errors.Is(err, admission.ErrInvalid) || errors.Is(err, admission.ErrPolicy) {
			return command.Exit(3, err)
		}
		return command.Exit(8, err)
	}
	return nil
}

func (s *settings) loadReviews(ctx context.Context, target common.Hash, keys *identity.Keys, use func(context.Context, admission.Diana, *mailbox.Client, *identity.Keys, []admission.Review) error) error {
	if _, err := protocol.Origin(s.mailbox); err != nil {
		return command.Exit(2, err)
	}
	pin, err := s.registry()
	if err != nil {
		return command.Exit(2, err)
	}
	relay, err := mailbox.NewClient(s.mailbox, keys)
	if err != nil {
		return command.Exit(2, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	messages, err := relay.Inbox(ctx)
	if err != nil {
		return command.Exit(8, err)
	}
	native := chain.Diana()
	evm, err := chain.Connect(ctx, native)
	if err != nil {
		return command.Exit(3, err)
	}
	defer evm.Close()
	authority := admission.Diana{Native: native, EVM: evm, Registry: pin, Cards: s.cardsDirectory(), Origin: s.mailbox}
	var reviews []admission.Review
	var unverified bool
	for _, message := range messages {
		review, err := admission.OpenReview(ctx, authority, keys, message, target)
		if err != nil {
			if !errors.Is(err, admission.ErrInvalid) && !errors.Is(err, admission.ErrExpired) && !errors.Is(err, admission.ErrPolicy) {
				unverified = true
			}
			continue
		}
		reviews = append(reviews, review)
		if target != (common.Hash{}) {
			break
		}
	}
	if target != (common.Hash{}) && len(reviews) == 0 {
		return command.Exit(3, errors.New("Couldn't find a verified request with that ID. It may have expired."))
	}
	if unverified && target == (common.Hash{}) {
		return command.Exit(3, errors.New("Couldn't verify every request. Check the current Door Cards and try again."))
	}
	return use(ctx, authority, relay, keys, reviews)
}
