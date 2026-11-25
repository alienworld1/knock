package admission

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knock/internal/chain"
	"knock/internal/door"
	"knock/internal/identity"

	qoreseal "github.com/qorechain/qoreseal/go"
)

// The Milestone 1 fixture supplies existing registered actors and a pinned
// registry. This test only reads chain state.
func TestDianaPrivateAdmission(t *testing.T) {
	path := os.Getenv("KNOCK_DIANA_FIXTURE")
	if path == "" {
		t.Skip("set KNOCK_DIANA_FIXTURE for the disposable Diana lab")
	}
	var fixture struct {
		Config                string `json:"config"`
		RevocationTransaction string `json:"revocationTransaction"`
		Profiles              map[string]struct {
			Profile    string `json:"profile"`
			Credential string `json:"credential"`
		} `json:"profiles"`
	}
	if err := door.ReadConfig(path, &fixture); err != nil {
		t.Fatal(err)
	}
	config, err := door.LoadConfig(fixture.Config)
	if err != nil {
		t.Fatal(err)
	}
	config.Cards = t.TempDir()
	config.Mailbox = "http://127.0.0.1:8180"
	load := func(role string) *identity.Keys {
		t.Helper()
		p := fixture.Profiles[role]
		pass, err := os.ReadFile(p.Credential)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(pass)
		keys, err := identity.Unlock(p.Profile, pass)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(keys.Clear)
		return keys
	}
	hostKeys, requester, approver, outsider := load("door"), load("requester"), load("approver"), load("outsider")
	publicCard := func(key *identity.Keys) qoreseal.RecipientCard {
		t.Helper()
		card, err := RecipientCard(key)
		if err != nil {
			t.Fatal(err)
		}
		return card
	}
	card, err := door.NewCard(config, config.Owner, hostKeys, publicCard(hostKeys), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := door.WriteCard(config.Cards, card); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	defer cancel()
	native := chain.Diana()
	evm, err := chain.Connect(ctx, native)
	if err != nil {
		t.Fatal(err)
	}
	defer evm.Close()
	authority := Diana{Native: native, EVM: evm, Registry: config.Registry, Cards: config.Cards, Origin: config.Mailbox, Expected: &config}
	if _, err := authority.Door(ctx, config.Account); err != nil {
		t.Fatalf("verified Door: %v", err)
	}
	actor := func(key *identity.Keys) Actor {
		t.Helper()
		actor, err := authority.Actor(ctx, card.Details, key.Account.Bech32, publicCard(key))
		if err != nil {
			t.Fatal(err)
		}
		return actor
	}
	doorActor, requesterActor, reviewer := actor(hostKeys), actor(requester), actor(approver)
	if len(config.Policy.Approvers) != 1 || config.Policy.Approvers[0] != reviewer.Binding.Account {
		t.Fatal("fixture must bind the disposable approver to the current policy")
	}
	journal, _ := journalAt(t, filepath.Join(t.TempDir(), "private", "journal"))
	host := Host{Authority: authority, Keys: hostKeys, Journal: journal}
	r, messages, err := buildRequest(requester, card, publicCard(requester), requesterActor.Binding, doorActor,
		[]Binding{reviewer.Binding}, []qoreseal.SealRecipient{reviewer.Recipient},
		config.Policy.Roles[0], time.Second, testReason, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Clear()
	var wrapped delivery
	if err := open(messages[1].Body, messages[1].ID, reviewDelivery, outsider.Recipient, 8, &wrapped); !errors.Is(err, ErrInvalid) {
		t.Fatalf("outsider opened the registered approver delivery: %v", err)
	}
	start := time.Now()
	if err := host.Receive(ctx, messages[0]); err != nil {
		t.Fatalf("Door request: %v", err)
	}
	t.Logf("verified Diana Door request in %s", time.Since(start).Round(time.Millisecond))
	review, err := OpenReview(ctx, authority, approver, messages[1], r.ID())
	if err != nil || review.Reason() != testReason || review.Summary().ID != r.ID() {
		t.Fatalf("verified Diana review: %v", err)
	}
	pass, err := review.Decision(ctx, authority, approver, Authorized)
	if err != nil {
		t.Fatalf("signed decision: %v", err)
	}
	start = time.Now()
	if err := host.Receive(ctx, pass); err != nil {
		t.Fatalf("verified Entry Pass and finalized revocation: %v", err)
	}
	t.Logf("verified Diana admission in %s", time.Since(start).Round(time.Millisecond))
	entry, err := journal.get(r.ID())
	if err != nil || entry.Outcome != Authorized || entry.Notice == nil {
		t.Fatalf("journal outcome: %v", err)
	}
	outcome, err := r.ReadStatus(ctx, authority, *entry.Notice)
	if err != nil || outcome != Authorized {
		t.Fatalf("verified one-time reply: %v", err)
	}
	for _, key := range []*identity.Keys{requester, approver, outsider} {
		var reply signedStatus
		if err := open(entry.Notice.Body, entry.Notice.ID, statusPurpose, key.Recipient, 1, &reply); !errors.Is(err, ErrInvalid) {
			t.Fatalf("a registered static key opened the reply: %v", err)
		}
	}
}
