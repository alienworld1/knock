package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"knock/internal/chain"
	"knock/internal/door"
	"knock/internal/identity"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
	bolt "go.etcd.io/bbolt"
)

const testReason = "Review the private approval fixture"

type testAuthority struct {
	card    door.Card
	actors  map[string]*identity.Keys
	revoked bool
}

func (a *testAuthority) Door(_ context.Context, account string) (door.Card, error) {
	if a.card.Details.Account != account {
		return door.Card{}, ErrInvalid
	}
	return a.card, nil
}

func (a *testAuthority) Actor(_ context.Context, _ door.Details, account string, card qoreseal.RecipientCard) (Actor, error) {
	keys := a.actors[account]
	if keys == nil {
		return Actor{}, ErrInvalid
	}
	public := keys.Signing.PublicKey
	recipient, err := qoreseal.VerifyRecipientCard(qoreseal.VerifyRecipientCardArgs{
		ChainID: chain.NativeID, Address: account, Card: card, PqPublicKey: public,
		MlkemPublicKey: keys.Recipient.MlkemPublicKey,
	})
	if err != nil {
		return Actor{}, ErrInvalid
	}
	return Actor{binding(account, public, recipient), public, recipient}, nil
}

func (a *testAuthority) CanAdmit(context.Context, door.Details, common.Hash) (bool, error) {
	return !a.revoked, nil
}

type harness struct {
	authority *testAuthority
	requester *identity.Keys
	approvers []*identity.Keys
	host      Host
}

func keys(t *testing.T, seed byte) *identity.Keys {
	t.Helper()
	classical, err := qoresign.ClassicalKeyFromPrivate(bytes.Repeat([]byte{seed}, 32), qoresign.EthSecp256k1)
	if err != nil {
		t.Fatal(err)
	}
	account, err := qoresign.AddressFromPublicKey(classical.PublicKey, classical.Type)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := qoresign.PqKeyFromSeed(bytes.Repeat([]byte{seed + 30}, 32))
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := qoreseal.SealKeysFromSeed(bytes.Repeat([]byte{seed + 60}, 32))
	if err != nil {
		t.Fatal(err)
	}
	result := &identity.Keys{Account: account, Classical: classical, Signing: signing, Recipient: recipient}
	t.Cleanup(result.Clear)
	return result
}

func newHarness(t *testing.T, count int) harness {
	t.Helper()
	host, requester := keys(t, 1), keys(t, 2)
	actors := map[string]*identity.Keys{host.Account.Bech32: host, requester.Account.Bech32: requester}
	var approvers []*identity.Keys
	for i := range count {
		actor := keys(t, byte(i)+3)
		actors[actor.Account.Bech32] = actor
		approvers = append(approvers, actor)
	}
	slices.SortFunc(approvers, func(a, b *identity.Keys) int { return bytes.Compare(a.Account.Bytes, b.Account.Bytes) })
	accounts := make([]string, 0, len(approvers))
	for _, actor := range approvers {
		accounts = append(accounts, actor.Account.Bech32)
	}
	cfg := door.Config{
		Registry: chain.Registry{Address: common.Address{1}, CodeHash: common.Hash{1}},
		DoorID:   common.Hash{2}, Account: host.Account.Bech32,
		Policy:  door.Policy{Version: 1, Enabled: true, MaxDurationSeconds: 120, Approvers: accounts, Roles: []string{"logs", "maintenance"}},
		Mailbox: "http://127.0.0.1:8180",
	}
	recipient, err := RecipientCard(host)
	if err != nil {
		t.Fatal(err)
	}
	card, err := door.NewCard(cfg, keys(t, 20).Account.Bech32, host, recipient, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	authority := &testAuthority{card: card, actors: actors}
	return harness{authority, requester, approvers, Host{Authority: authority, Keys: host}}
}

func (h harness) request(t *testing.T, at time.Time) (*Request, []mailbox.Message) {
	t.Helper()
	requester, err := RecipientCard(h.requester)
	if err != nil {
		t.Fatal(err)
	}
	card := h.authority.card
	host, err := h.authority.Actor(t.Context(), card.Details, card.Details.Account, card.Details.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	var bindings []Binding
	var recipients []qoreseal.SealRecipient
	for _, actor := range h.approvers {
		bindings = append(bindings, localBinding(actor))
		recipients = append(recipients, qoreseal.RecipientOf(actor.Recipient))
	}
	request, messages, err := buildRequest(h.requester, card, requester, localBinding(h.requester), host,
		bindings, recipients, "logs", time.Minute, testReason, at)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(request.Clear)
	return request, messages
}

func (h harness) decisions(t *testing.T, msgs []mailbox.Message, index int, outcome Outcome) mailbox.Message {
	t.Helper()
	review, err := OpenReview(t.Context(), h.authority, h.approvers[index], msgs[index+1], common.Hash{})
	if err != nil {
		t.Fatal(err)
	}
	if review.Reason() != testReason || review.Summary().Role != "logs" || review.Summary().Seconds != 60 {
		t.Fatal("review differs from the signed request")
	}
	decision, err := review.Decision(t.Context(), h.authority, h.approvers[index], outcome)
	if err != nil {
		t.Fatal(err)
	}
	return decision
}

func journalAt(t *testing.T, path string) (*Journal, *bolt.DB) {
	t.Helper()
	db, err := protocol.OpenState(path)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := NewJournal(db)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return journal, db
}

func TestAdmissionRecipientIsolationAndConcurrentDecisions(t *testing.T) {
	h := newHarness(t, 8)
	path := filepath.Join(t.TempDir(), "private", "db")
	journal, db := journalAt(t, path)
	h.host.Journal = journal
	request, messages := h.request(t, time.Now())
	if len(messages) != 9 || len(messages[1].Body) >= protocol.MaxEnvelope {
		t.Fatal("eight-approver request exceeded the Mailbox limit")
	}
	t.Logf("eight-approver outer envelope: %d bytes", len(messages[1].Body))
	for _, message := range messages {
		if bytes.Contains(message.Body, []byte(testReason)) {
			t.Fatal("reason in transport")
		}
	}
	outsider := keys(t, 21)
	for _, key := range []*identity.Keys{outsider, h.host.Keys, h.requester} {
		var review delivery
		if open(messages[1].Body, messages[1].ID, reviewDelivery, key.Recipient, 8, &review) == nil {
			t.Fatal("unintended recipient opened the approval delivery")
		}
	}
	var wrapper delivery
	msg := messages[0]
	if err := open(msg.Body, msg.ID, doorDelivery, h.host.Keys.Recipient, 1, &wrapper); err != nil {
		t.Fatal(err)
	}
	raw, err := qoreseal.Open(qoreseal.OpenArgs{
		Envelope: wrapper.Inner, Keys: h.host.Keys.Recipient, ChainID: chain.NativeID, Purpose: doorInner, AAD: msg.ID[:],
	})
	if err != nil || bytes.Contains(raw, []byte(testReason)) {
		t.Fatal("Door payload unavailable or contains reason")
	}
	for i := range h.approvers {
		review, err := OpenReview(t.Context(), h.authority, h.approvers[i], messages[i+1], request.ID())
		if err != nil || review.Summary().ID != request.ID() {
			t.Fatalf("approval recipient %d: %v", i, err)
		}
	}
	// Targeted review rejects unrelated IDs before consulting Diana.
	if _, err := OpenReview(t.Context(), nil, h.approvers[0], messages[1], common.Hash{1}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unrelated review target: %v", err)
	}
	grant := h.decisions(t, messages, 0, Authorized)
	deny := h.decisions(t, messages, 1, Denied)
	if err := h.host.Receive(t.Context(), grant); !errors.Is(err, ErrPending) {
		t.Fatalf("out-of-order decision: %v", err)
	}
	for range 2 {
		if err := h.host.Receive(t.Context(), msg); err != nil {
			t.Fatal(err)
		}
	}
	errs := make(chan error, 2)
	var group sync.WaitGroup
	for _, decision := range []mailbox.Message{grant, deny} {
		group.Go(func() { errs <- h.host.Receive(t.Context(), decision) })
	}
	group.Wait()
	close(errs)
	successes := 0
	for err := range errs {
		if err == nil {
			successes++
		} else if !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	if successes != 1 {
		t.Fatalf("accepted %d terminal outcomes", successes)
	}

	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	journal, _ = journalAt(t, path)
	h.host.Journal = journal
	entry, err := journal.get(request.ID())
	if err != nil || entry.Delivery != nil || entry.Notice == nil {
		t.Fatalf("unexpected reopened journal: %v", err)
	}
	winner, loser := grant, deny
	if entry.Outcome == Denied {
		winner, loser = loser, winner
	}
	if err := h.host.Receive(t.Context(), winner); err != nil {
		t.Fatal(err)
	}
	if err := h.host.Receive(t.Context(), loser); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replayed conflict: %v", err)
	}
	outcome, err := request.ReadStatus(t.Context(), h.authority, *entry.Notice)
	if err != nil || outcome != entry.Outcome {
		t.Fatalf("reply %s: %v", outcome, err)
	}
	for _, key := range []*identity.Keys{h.requester, h.approvers[0], outsider, h.host.Keys} {
		var status signedStatus
		if open(entry.Notice.Body, entry.Notice.ID, statusPurpose, key.Recipient, 1, &status) == nil {
			t.Fatal("static or unrelated key opened the one-time response")
		}
	}
	var status signedStatus
	for _, test := range []struct {
		chain, purpose string
		id             common.Hash
	}{
		{"wrong-network", statusPurpose, entry.Notice.ID},
		{chain.NativeID, decisionPurpose, entry.Notice.ID},
		{chain.NativeID, statusPurpose, common.Hash{1}},
	} {
		if _, err := qoreseal.Open(qoreseal.OpenArgs{
			ChainID: test.chain, Purpose: test.purpose, Keys: request.reply, Envelope: entry.Notice.Body, AAD: test.id[:],
		}); err == nil {
			t.Fatal("wrong reply context opened the envelope")
		}
	}
	if err := open(entry.Notice.Body, entry.Notice.ID, statusPurpose, request.reply, 1, &status); err != nil {
		t.Fatal(err)
	}
	status.Record.Reply[0] ^= 1
	status.Signature, err = protocol.Sign(h.host.Keys, statusPurpose, status.Record)
	if err != nil {
		t.Fatal(err)
	}
	wrong := *entry.Notice
	wrong.Body, err = seal(status, wrong.ID, statusPurpose, qoreseal.RecipientOf(request.reply))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := request.ReadStatus(t.Context(), h.authority, wrong); !errors.Is(err, ErrInvalid) {
		t.Fatalf("substituted reply key verified: %v", err)
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(contents, []byte(testReason)) || bytes.Contains(contents, request.reply.MlkemSecretKey) {
		t.Fatal("private reason or temporary reply key in journal")
	}
}

func TestAdmissionRejectsTamperingAndStaleState(t *testing.T) {
	h := newHarness(t, 2)
	h.host.Journal, _ = journalAt(t, filepath.Join(t.TempDir(), "private", "db"))
	request, messages := h.request(t, time.Now())
	grant := h.decisions(t, messages, 0, Authorized)

	broken := messages[0]
	broken.Body = bytes.Clone(broken.Body)
	broken.Body[len(broken.Body)-1] ^= 1
	if err := h.host.Receive(t.Context(), broken); !errors.Is(err, ErrInvalid) {
		t.Fatalf("tampered envelope: %v", err)
	}
	var wrapper delivery
	if err := open(messages[1].Body, messages[1].ID, reviewDelivery, h.approvers[0].Recipient, 8, &wrapper); err != nil {
		t.Fatal(err)
	}
	wrapper.Manifest.Signature.Pq.Signature = "modified"
	modified := messages[1]
	reviewers := []qoreseal.SealRecipient{qoreseal.RecipientOf(h.approvers[0].Recipient), qoreseal.RecipientOf(h.approvers[1].Recipient)}
	var err error
	modified.Body, err = seal(wrapper, modified.ID, reviewDelivery, reviewers...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReview(t.Context(), h.authority, h.approvers[0], modified, request.ID()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("modified requester signature: %v", err)
	}
	if err := h.host.Receive(t.Context(), messages[0]); err != nil {
		t.Fatal(err)
	}

	var original signedDecision
	if err := open(grant.Body, grant.ID, decisionPurpose, h.host.Keys.Recipient, 1, &original); err != nil {
		t.Fatal(err)
	}
	other := keys(t, 22)
	for name, mutate := range map[string]func(*decision){
		"duration":  func(d *decision) { d.Authorization.Seconds++ },
		"role":      func(d *decision) { d.Authorization.Role = "maintenance" },
		"network":   func(d *decision) { d.Authorization.Native = "elsewhere" },
		"purpose":   func(d *decision) { d.Authorization.Service = "http" },
		"key":       func(d *decision) { d.Authorization.Requester.KEM[0] ^= 1 },
		"requester": func(d *decision) { d.Authorization.Requester.Account = other.Account.Bech32 },
		"envelope":  func(d *decision) { d.DoorEnvelope = sha256.Sum256([]byte("other envelope")) },
	} {
		t.Run(name, func(t *testing.T) {
			record := original.Record
			mutate(&record)
			sig, err := protocol.Sign(h.approvers[0], decisionPurpose, record)
			if err != nil {
				t.Fatal(err)
			}
			altered := grant
			altered.Body, err = seal(signedDecision{record, sig}, grant.ID, decisionPurpose, qoreseal.RecipientOf(h.host.Keys.Recipient))
			if err != nil {
				t.Fatal(err)
			}
			if err := h.host.Receive(t.Context(), altered); !errors.Is(err, ErrInvalid) {
				t.Fatalf("altered decision: %v", err)
			}
		})
	}
	for _, signer := range []*identity.Keys{other, h.approvers[0]} {
		sig, err := protocol.Sign(signer, decisionPurpose, original.Record)
		if err != nil {
			t.Fatal(err)
		}
		if signer == h.approvers[0] {
			sig.Pq = nil
		}
		forged := grant
		forged.Body, err = seal(signedDecision{original.Record, sig}, grant.ID, decisionPurpose, qoreseal.RecipientOf(h.host.Keys.Recipient))
		if err != nil {
			t.Fatal(err)
		}
		if err := h.host.Receive(t.Context(), forged); !errors.Is(err, ErrInvalid) {
			t.Fatalf("wrong or classical-only signer: %v", err)
		}
	}
	h.authority.revoked = true
	if err := h.host.Receive(t.Context(), grant); !errors.Is(err, ErrInvalid) {
		t.Fatalf("revoked request: %v", err)
	}
	h.authority.revoked = false
	h.authority.card.Details.Policy.Version++
	if err := h.host.Receive(t.Context(), grant); !errors.Is(err, ErrPolicy) {
		t.Fatalf("changed policy: %v", err)
	}
	h.authority.card.Details.Policy.Version--
	rotated := *h.requester
	rotated.Recipient = other.Recipient
	h.authority.actors[h.requester.Account.Bech32] = &rotated
	if err := h.host.Receive(t.Context(), grant); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stale requester key: %v", err)
	}
	h.authority.actors[h.requester.Account.Bech32] = h.requester
	rotatedApprover := *h.approvers[0]
	rotatedApprover.Signing = other.Signing
	h.authority.actors[rotatedApprover.Account.Bech32] = &rotatedApprover
	if err := h.host.Receive(t.Context(), grant); !errors.Is(err, ErrInvalid) {
		t.Fatalf("stale approver key: %v", err)
	}
	h.authority.actors[rotatedApprover.Account.Bech32] = h.approvers[0]
	if err := h.host.Receive(t.Context(), grant); err != nil {
		t.Fatal(err)
	}
	entry, err := h.host.Journal.get(request.ID())
	if err != nil || entry.Outcome != Authorized {
		t.Fatalf("valid grant did not authorize: %v", err)
	}
}

func TestAdmissionExpiryIsTerminal(t *testing.T) {
	h := newHarness(t, 1)
	h.host.Journal, _ = journalAt(t, filepath.Join(t.TempDir(), "private", "db"))
	r, msgs := h.request(t, time.Now())
	decision := h.decisions(t, msgs, 0, Denied)
	if err := h.host.Receive(t.Context(), msgs[0]); err != nil {
		t.Fatal(err)
	}
	if err := h.host.Journal.expire(r.Deadline().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := h.host.Receive(t.Context(), decision); !errors.Is(err, ErrInvalid) {
		t.Fatalf("decision after expiry: %v", err)
	}
	item, err := h.host.Journal.get(r.ID())
	if err != nil || item.Outcome != Expired || item.Notice != nil || item.Delivery != nil {
		t.Fatalf("expiry issued an outcome or kept pending data: %v", err)
	}
	_, expired := h.request(t, time.Now().Add(-RequestLifetime-time.Second))
	if err := h.host.Receive(t.Context(), expired[0]); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired delivery: %v", err)
	}
}

func TestAuthorizationCanonicalEncoding(t *testing.T) {
	body := authorization{Version: 1, Native: chain.NativeID, EVM: chain.EVMID, Role: "logs", Seconds: 60}
	digest, err := protocol.Digest(body)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "0xb607017217c596d26961d52b9b38ae20b39e0e1b64231c142783401eecd8962a"
	if digest.Hex() != expected {
		t.Fatalf("canonical authorization vector: %s", digest.Hex())
	}
	raw, err := protocol.Encode(body)
	if err != nil {
		t.Fatal(err)
	}
	for _, invalid := range [][]byte{
		append(bytes.Clone(raw), 0), {0xbf, 0xff}, {0xa1, 0x61, 'x', 0xf4}, {0xa2, 0x61, 'x', 0xf4, 0x61, 'x', 0xf5},
	} {
		var decoded authorization
		if protocol.Decode(invalid, &decoded) == nil {
			t.Fatal("accepted invalid CBOR")
		}
	}
}
