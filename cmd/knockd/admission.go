package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"knock/internal/admission"
	"knock/internal/chain"
	"knock/internal/command"
	"knock/internal/door"
	"knock/internal/identity"
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
)

func mailboxCommand() *cobra.Command {
	var address, origin, state string
	cmd := &cobra.Command{
		Use: "mailbox", Short: "Run the private admission Mailbox", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			host, _, err := net.SplitHostPort(address)
			ip, badIP := netip.ParseAddr(host)
			if err != nil || badIP != nil || !ip.IsLoopback() {
				return command.Exit(2, errors.New("set a loopback listen address with a port"))
			}
			if _, err := protocol.Origin(origin); err != nil {
				return command.Exit(2, err)
			}
			if state == "" {
				return command.Exit(2, errors.New("set the Mailbox --state file"))
			}
			db, err := protocol.OpenState(state)
			if err != nil {
				return command.Exit(8, err)
			}
			defer db.Close()
			mail, err := mailbox.NewServer(db, chain.Diana(), origin)
			if err != nil {
				return command.Exit(8, err)
			}
			listener, err := net.Listen("tcp", address)
			if err != nil {
				return command.Exit(8, err)
			}
			server := &http.Server{
				Handler: mail, ReadHeaderTimeout: 4 * time.Second, ReadTimeout: 10 * time.Second,
				WriteTimeout: 12 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8 << 10,
			}
			fmt.Fprintf(cmd.ErrOrStderr(), "Mailbox listening on %s\n", listener.Addr())
			group, ctx := errgroup.WithContext(cmd.Context())
			group.Go(func() error {
				if err := server.Serve(listener); !errors.Is(err, http.ErrServerClosed) {
					return err
				}
				return nil
			})
			group.Go(func() error { return mail.Maintain(ctx) })
			group.Go(func() error {
				<-ctx.Done()
				call, cancel := context.WithTimeout(context.Background(), 12*time.Second)
				defer cancel()
				if err := server.Shutdown(call); err != nil {
					_ = server.Close()
					return err
				}
				return nil
			})
			return command.Exit(8, group.Wait())
		},
	}
	cmd.Flags().StringVar(&address, "listen", "127.0.0.1:8180", "loopback HTTP listen address")
	cmd.Flags().StringVar(&origin, "origin", "http://127.0.0.1:8180", "public origin bound to authentication")
	cmd.Flags().StringVar(&state, "state", "", "private Mailbox state file")
	return cmd
}

func serveAdmission(cmd *cobra.Command, config door.Config, keys *identity.Keys) error {
	if _, err := protocol.Origin(config.Mailbox); err != nil {
		return command.Exit(2, err)
	}
	if config.State == "" || keys.Account.Bech32 != config.Account {
		return command.Exit(2, errors.New("set a private admission state file and the configured Door's profile"))
	}
	db, err := protocol.OpenState(config.State)
	if err != nil {
		return command.Exit(8, err)
	}
	defer db.Close()
	journal, err := admission.NewJournal(db)
	if err != nil {
		return command.Exit(8, err)
	}
	call, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	native := chain.Diana()
	evm, err := chain.Connect(call, native)
	if err != nil {
		return command.Exit(3, err)
	}
	defer evm.Close()
	authority := admission.Diana{
		Native: native, EVM: evm, Registry: config.Registry, Cards: config.Cards, Origin: config.Mailbox, Expected: &config,
	}
	card, err := authority.Door(call, config.Account)
	if err != nil {
		return command.Exit(3, err)
	}
	actor, err := admission.CardBinding(card)
	if err != nil {
		return command.Exit(3, err)
	}
	if !actor.Matches(keys) {
		return command.Exit(3, errors.New("local Door keys differ from the current Card"))
	}
	relay, err := mailbox.NewClient(config.Mailbox, keys)
	if err != nil {
		return command.Exit(2, err)
	}
	host := admission.Host{Authority: authority, Keys: keys, Journal: journal, Progress: command.Progress}
	if config.WireGuardEndpoint != "" {
		host.SSH, err = lease.StartHost(call, config.WireGuardEndpoint)
		if err != nil {
			return command.Exit(6, err)
		}
		defer host.SSH.Release()
		group, ctx := errgroup.WithContext(cmd.Context())
		fmt.Fprintln(cmd.ErrOrStderr(), "Door verified. SSH access is closed until approval.")
		group.Go(func() error { return host.MonitorSSH(ctx) })
		group.Go(func() error { return pollAdmission(ctx, cmd, host, relay) })
		err = group.Wait()
		cleanup, stop := context.WithTimeout(context.Background(), 18*time.Second)
		defer stop()
		if cleanupErr := host.SSH.CloseCurrent(cleanup); cleanupErr != nil {
			return command.Exit(7, errors.Join(err, cleanupErr))
		}
		return command.Exit(8, err)
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "Door verified and closed")
	return pollAdmission(cmd.Context(), cmd, host, relay)
}

func pollAdmission(ctx context.Context, cmd *cobra.Command, host admission.Host, relay *mailbox.Client) error {
	failures := 0
	for {
		err := host.Poll(ctx, relay)
		if ctx.Err() != nil {
			return nil
		}
		if err != nil && failures == 0 {
			fmt.Fprintln(cmd.ErrOrStderr(), "Admission delivery or verification unavailable. Retrying.")
		}
		if err == nil && failures != 0 {
			fmt.Fprintln(cmd.ErrOrStderr(), "Admission polling resumed")
		}
		if err != nil {
			failures = min(failures+1, 3)
		} else {
			failures = 0
		}
		timer := time.NewTimer(mailbox.PollDelay(failures))
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}
