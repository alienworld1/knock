package admission

import (
	"context"
	"errors"
	"math/big"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"knock/internal/chain"
	"knock/internal/door"
	"knock/internal/identity"
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
)

type paymentFixture struct {
	*testAuthority
	pass     chain.Purchase
	consumed int
}

func (f *paymentFixture) Payment(context.Context, chain.Registry, common.Hash) (chain.Purchase, error) {
	return f.pass, nil
}

func (f *paymentFixture) Consume(context.Context, chain.Registry, common.Hash, common.Hash, common.Hash, uint64, uint64, *identity.Keys, func(string)) error {
	f.consumed++
	return errors.New("unexpected consumption attempt")
}

func TestMeteredDoorRejectsUnfinalizedAndMismatchedPurchases(t *testing.T) {
	h := newHarness(t, 1)
	d := h.authority.card.Details
	policy := door.Policy{Version: d.Policy.Version, Enabled: true, MaxDurationSeconds: 60,
		Offer: &door.Offer{ID: common.Hash{7}, Service: "private-status", PriceUQOR: 1, Beneficiary: d.Owner}}
	card, err := door.NewCard(door.Config{Registry: d.Registry, DoorID: d.DoorID, Policy: policy, Mailbox: d.Mailbox},
		d.Owner, h.host.Keys, d.Recipient, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h.authority.card = card
	fixture := &paymentFixture{testAuthority: h.authority}
	h.host.Authority, h.host.SSH = fixture, &lease.Host{}
	h.host.Journal, _ = journalAt(t, filepath.Join(t.TempDir(), "admission", "door.db"))
	h.host.publish = func(context.Context, mailbox.Message) error { return errors.New("unexpected response") }
	request, messages, err := BuildRequest(t.Context(), fixture, nil, h.requester, card, "", time.Minute, "")
	if err != nil {
		t.Fatal(err)
	}
	defer request.Clear()
	if len(messages) != 1 || messages[0].Route != d.Account || len(request.ssh) != 0 {
		t.Fatal("metered request did not use a single private Door delivery")
	}
	offer, err := policy.PaymentOffer()
	if err != nil {
		t.Fatal(err)
	}
	expect := chain.Purchase{DoorId: d.DoorID, Buyer: common.BytesToAddress(h.requester.Account.Bytes),
		Offer: offer, RedeemBy: uint64(request.Deadline().Unix())}
	cases := []struct {
		name   string
		change func(*chain.Purchase)
		err    error
	}{
		{"no finalized purchase", func(p *chain.Purchase) { *p = chain.Purchase{} }, ErrPending},
		{"wrong buyer", func(p *chain.Purchase) { p.Buyer = common.Address{1} }, ErrInvalid},
		{"wrong Door", func(p *chain.Purchase) { p.DoorId = common.Hash{1} }, ErrInvalid},
		{"wrong offer", func(p *chain.Purchase) { p.Offer.Id = common.Hash{1} }, ErrInvalid},
		{"wrong amount", func(p *chain.Purchase) { p.Offer.Amount = big.NewInt(1) }, ErrInvalid},
		{"wrong beneficiary", func(p *chain.Purchase) { p.Offer.Beneficiary = common.Address{1} }, ErrInvalid},
		{"wrong version", func(p *chain.Purchase) { p.Offer.Version++ }, ErrInvalid},
		{"wrong duration", func(p *chain.Purchase) { p.Offer.Duration++ }, ErrInvalid},
		{"wrong deadline", func(p *chain.Purchase) { p.RedeemBy++ }, ErrInvalid},
		{"consumed", func(p *chain.Purchase) { p.SessionRef = common.Hash{1} }, ErrInvalid},
		{"revoked", func(*chain.Purchase) { h.authority.revoked = true }, ErrPolicy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture.pass = expect
			tc.change(&fixture.pass)
			if err := h.host.Receive(t.Context(), messages[0]); !errors.Is(err, tc.err) {
				t.Fatalf("got %v, want %v", err, tc.err)
			}
			entry, err := h.host.Journal.get(request.ID())
			if err != nil || entry.PaymentReserved || entry.Lease != nil || fixture.consumed != 0 {
				t.Fatalf("invalid purchase reached consumption or host provisioning: %v", err)
			}
		})
	}
}

func TestPaymentReservationSurvivesInterruptedConsumption(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admission", "door.db")
	db, err := protocol.OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	id, commitment := common.Hash{1}, common.Hash{2}
	message := mailbox.Message{Expires: time.Now().Add(time.Minute).Unix()}
	if err := journal.accept(id, commitment, message); err != nil {
		t.Fatal(err)
	}
	var reservations atomic.Int32
	var attempts sync.WaitGroup
	for range 8 {
		attempts.Go(func() {
			reserved, err := journal.reservePayment(id, commitment)
			if err != nil {
				t.Error(err)
			}
			if reserved {
				reservations.Add(1)
			}
		})
	}
	attempts.Wait()
	if got := reservations.Load(); got != 1 {
		t.Fatalf("got %d consumption claims, want 1", got)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	// The first process lost the consumption response before it could begin provisioning.
	db, err = protocol.OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	journal, err = NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.accept(id, commitment, message); err != nil {
		t.Fatal(err)
	}
	if reserved, err := journal.reservePayment(id, commitment); err != nil || reserved {
		t.Fatalf("replayed payment acquired a second reservation: %v, %v", reserved, err)
	}
	sessions, err := journal.sessions()
	if err != nil || len(sessions) != 0 {
		t.Fatalf("interrupted consumption produced a host lease: %v, %v", sessions, err)
	}
}
