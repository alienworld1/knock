package admission

import (
	"errors"
	"path/filepath"
	"testing"
	"time"

	"knock/internal/chain"
	"knock/internal/identity"
	"knock/internal/lease"
	"knock/internal/mailbox"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
)

func TestRevocationEvidenceSurvivesCleanupFailure(t *testing.T) {
	h := newHarness(t, 1)
	h.host.Journal, _ = journalAt(t, filepath.Join(t.TempDir(), "private", "db"))
	request, _ := h.request(t, time.Now())
	id := request.ID()
	a := request.auth
	ref := SessionReference(a.DoorID, id)
	to := []sessionRecipient{
		{h.requester.Account.Bech32, qoreseal.RecipientOf(h.requester.Recipient)},
		{h.approvers[0].Account.Bech32, qoreseal.RecipientOf(h.approvers[0].Recipient)},
	}
	targets, err := h.host.sealSessionRecipients(ref, a, to)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	digest := common.Hash{10}
	j := h.host.Journal
	if err := j.accept(id, digest, mailbox.Message{Expires: now.Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	record := leaseRecord{ID: ref, Issued: now.Unix(), Deadline: now.Add(time.Minute).Unix(), State: lease.Reserved}
	accepted, err := j.decide(id, digest, common.Hash{11}, Authorized, nil, &record, targets)
	if err != nil || !accepted {
		t.Fatalf("could not reserve test grant: %v", err)
	}
	if err := j.updateLease(id, lease.Provisioning, nil); err != nil {
		t.Fatal(err)
	}
	block := common.Hash{44}
	observation := chain.RevocationObservation{Height: 50, Block: block, Observed: now}
	if err := h.host.updateMonitoring(id, now, true, observation, true); err != nil {
		t.Fatal(err)
	}
	if err := j.updateLease(id, lease.Ready, nil); err == nil {
		t.Fatal("revoked grant became eligible for publication")
	}
	status := func(state lease.State) SessionStatus {
		t.Helper()
		if err := h.host.queueSessionStatus(t.Context()); err != nil {
			t.Fatal(err)
		}
		item, err := j.get(id)
		if err != nil || item.Evidence == nil || len(item.Evidence.Outbox) != len(to) {
			t.Fatalf("missing encrypted status: %v", err)
		}
		card := h.authority.card
		audiences := []*identity.Keys{h.requester, h.approvers[0]}
		var latest SessionStatus
		for i, message := range item.Evidence.Outbox {
			latest, err = readSessionStatus(card, audiences[i], message)
			if err != nil || latest.State != state || latest.RevokedBlock != block || latest.Cause != "Revoked" {
				t.Fatalf("incorrect status: %+v %v", latest, err)
			}
			wrong := audiences[1-i]
			message.Route = wrong.Account.Bech32
			if _, err := readSessionStatus(card, wrong, message); !errors.Is(err, ErrInvalid) {
				t.Fatal("another recipient opened a targeted status delivery")
			}
		}
		return latest
	}
	closing := status(lease.Closing)
	if closing.ClosedAt != 0 {
		t.Fatal("chain observation implied closure")
	}
	if changed, err := h.host.recordHostState(id, lease.Observation{State: lease.CleanupIncomplete}); err != nil || !changed {
		t.Fatal("could not record incomplete cleanup", err)
	}
	incomplete := status(lease.CleanupIncomplete)
	if incomplete.Revision <= closing.Revision || incomplete.ClosedAt != 0 {
		t.Fatal("incomplete cleanup was reported as verified closure")
	}
	if changed, err := h.host.recordHostState(id, lease.Observation{State: lease.Closed}); err != nil || !changed {
		t.Fatal("could not record verified closure", err)
	}
	closed := status(lease.Closed)
	if closed.Revision <= incomplete.Revision || closed.ClosedAt == 0 {
		t.Fatal("verified cleanup was not recorded in a new revision")
	}
	if err := j.updateLease(id, lease.Ready, nil); err == nil {
		t.Fatal("closed grant reopened")
	}
	if accepted, err := j.decide(id, digest, common.Hash{11}, Authorized, nil, &record, targets); err != nil || accepted {
		t.Fatalf("consumed approval was reusable: %v", err)
	}
}
