package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	bolt "go.etcd.io/bbolt"

	"knock/internal/chain"
	"knock/internal/identity"
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"
)

func TestAuditRotationRequiresCurrentOwner(t *testing.T) {
	h := newHarness(t, 1)
	audit := newTestAudit(t, &h)
	owner := keys(t, 20)
	h.authority.actors[owner.Account.Bech32] = owner
	auditor := h.approvers[0]
	auditorCard, err := RecipientCard(auditor)
	if err != nil {
		t.Fatal(err)
	}
	h.host.lookup = func(ctx context.Context, account string) (qoreseal.RecipientCard, error) {
		if account != auditor.Account.Bech32 {
			t.Fatalf("looked up an unexpected member %q", account)
		}
		return auditorCard, nil
	}
	makeMessage := func(r rotation, signer *identity.Keys) mailbox.Message {
		t.Helper()
		sig, err := protocol.Sign(signer, auditRotatePurpose, r)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := protocol.Digest(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := seal(signedRotation{r, sig}, ref, auditRotatePurpose, qoreseal.RecipientOf(h.host.Keys.Recipient))
		if err != nil {
			t.Fatal(err)
		}
		return mailbox.Message{Route: h.host.Keys.Account.Bech32, ID: ref, Expires: r.Expires, Body: body}
	}
	r := rotation{
		Group: audit.group, Policy: h.authority.card.Details.PolicyCommitment,
		Members: []string{auditor.Account.Bech32}, Expires: time.Now().Add(time.Minute).Unix(),
	}
	if err := h.host.Receive(t.Context(), makeMessage(r, auditor)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("auditor could rotate the group: %v", err)
	}
	oldPolicy := r
	oldPolicy.Policy[0] ^= 1
	if err := h.host.Receive(t.Context(), makeMessage(oldPolicy, owner)); !errors.Is(err, ErrPolicy) {
		t.Fatalf("owner rotated using the wrong policy: %v", err)
	}
	original := makeMessage(r, owner)
	if err := h.host.Receive(t.Context(), original); err != nil {
		t.Fatal(err)
	}
	if err := h.host.Receive(t.Context(), original); !errors.Is(err, ErrPolicy) {
		t.Fatalf("replayed rotation: %v", err)
	}
	r.From, r.Members = 1, nil
	if err := h.host.Receive(t.Context(), makeMessage(r, owner)); err != nil {
		t.Fatal(err)
	}
	state, err := audit.recover(h.host.Keys)
	if err != nil || state.Key.Epoch != 2 || len(state.Members) != 0 {
		t.Fatalf("couldn't remove the last member: %v", err)
	}
}

func TestAuditReceiptsFollowRotationAndPreserveCorrection(t *testing.T) {
	h := newHarness(t, 1)
	audit := newTestAudit(t, &h)
	current, removed, outsider := keys(t, 60), keys(t, 61), keys(t, 62)
	members := testAuditMembers(current, removed)
	if err := audit.rotate(h.host.Keys, 0, members); err != nil {
		t.Fatal(err)
	}
	requestID := auditSession(t, &h, false)
	if _, err := h.host.recordHostState(requestID, lease.Observation{State: lease.CleanupIncomplete, Cause: "Expired"}); err != nil {
		t.Fatal(err)
	}
	if err := h.host.maintainAudit(t.Context()); err != nil {
		t.Fatal(err)
	}
	item, err := h.host.Journal.get(requestID)
	if err != nil || len(item.Evidence.Receipts) != 1 {
		t.Fatalf("missing archived receipt: %v", err)
	}
	oldID := item.Evidence.Receipts[0]
	first, firstBundle := exportAudit(t, h, oldID, current)
	if old, _ := exportAudit(t, h, oldID, removed); old != first {
		t.Fatal("original epoch members read different outcomes")
	}
	if first.Cleanup != lease.CleanupIncomplete || first.Cause != "Expired" || first.Epoch != 1 ||
		first.Approver != h.approvers[0].Account.Bech32 || first.Request != requestID ||
		first.Requester != h.requester.Account.Bech32 || first.ActiveObservedAt == 0 || first.Corrects != (common.Hash{}) {
		t.Fatalf("incorrect original receipt: %+v", first)
	}
	if _, err := openAuditBundle(h.authority.card, outsider, firstBundle); err == nil {
		t.Fatal("unauthorized identity opened a receipt")
	}
	oldKey, err := qoreseal.OpenEpochKey(chain.NativeID, auditPurpose(audit.group), firstBundle.Distribution.Record.Envelope, removed.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(oldKey.Key)

	if err := audit.rotate(h.host.Keys, 1, testAuditMembers(current)); err != nil {
		t.Fatal(err)
	}
	if err := audit.rotate(h.host.Keys, 1, members); !errors.Is(err, ErrPolicy) {
		t.Fatalf("stale rotation result: %v", err)
	}
	if _, err := h.host.recordHostState(requestID, lease.Observation{State: lease.Closed}); err != nil {
		t.Fatal(err)
	}
	if err := h.host.maintainAudit(t.Context()); err != nil {
		t.Fatal(err)
	}
	item, err = h.host.Journal.get(requestID)
	if err != nil || len(item.Evidence.Receipts) != 2 || item.Evidence.Receipts[0] != oldID {
		t.Fatalf("correction did not preserve original: %v", err)
	}
	corrected, correctedBundle := exportAudit(t, h, item.Evidence.Receipts[1], current)
	if corrected.Epoch != 2 || corrected.Index <= first.Index || corrected.Corrects != oldID ||
		corrected.Cleanup != lease.Closed || corrected.TerminationObservedAt != first.TerminationObservedAt || corrected.Session != first.Session {
		t.Fatalf("incorrect correction: %+v", corrected)
	}
	if _, err := ExportAuditReceipt(audit.db, corrected.ID, removed.Account.Bech32); err == nil {
		t.Fatal("archive served a removed identity a new-epoch receipt")
	}
	if _, err := openAuditBundle(h.authority.card, removed, correctedBundle); err == nil {
		t.Fatal("removed identity opened the new distribution")
	}
	if _, err := qoreseal.OpenBatch(correctedBundle.Blob, func(uint64) ([]byte, bool) { return oldKey.Key, true }); err == nil {
		t.Fatal("old epoch key decrypted the correction")
	}
	if old, _ := exportAudit(t, h, oldID, removed); old != first {
		t.Fatal("old authorized history changed after rotation")
	}
	paidID := auditSession(t, &h, true)
	if _, err := h.host.recordHostState(paidID, lease.Observation{State: lease.Closed, Cause: "Revoked"}); err != nil {
		t.Fatal(err)
	}
	if err := h.host.maintainAudit(t.Context()); err != nil {
		t.Fatal(err)
	}
	payment, err := h.host.Journal.get(paidID)
	if err != nil || len(payment.Evidence.Receipts) != 1 {
		t.Fatalf("paid receipt not archived: %v", err)
	}
	paid, _ := exportAudit(t, h, payment.Evidence.Receipts[0], current)
	if paid.Service != "private-status" || paid.Purchase != payment.Manifest || paid.ConsumptionTx != payment.Lease.ConsumptionTx ||
		paid.Purchase == (common.Hash{}) || paid.ConsumptionTx == (common.Hash{}) || paid.Approver != "" {
		t.Fatalf("paid authorization not bound: %+v", paid)
	}

	// The durable copy imports without the Mailbox and stays encrypted in the cache.
	_, cache := journalAt(t, filepath.Join(t.TempDir(), "cache", "db"))
	raw, err := protocol.Encode(correctedBundle)
	if err != nil {
		t.Fatal(err)
	}
	if err := ImportAuditReceipt(cache, h.authority.card, current, raw); err != nil {
		t.Fatal(err)
	}
	history, err := LoadHistory(t.Context(), cache, nil, h.authority.card, current)
	if err != nil || len(history) != 1 || history[0] != corrected {
		t.Fatalf("archive recovery: %+v, %v", history, err)
	}
	cacheData, err := os.ReadFile(cache.Path())
	if err != nil || bytes.Contains(cacheData, []byte(corrected.Requester)) || bytes.Contains(cacheData, oldKey.Key) {
		t.Fatalf("local History persisted plaintext or epoch keys: %v", err)
	}
	deliveryBroken := errors.New("Mailbox offline")
	if err := audit.deliver(t.Context(), func(_ context.Context, m mailbox.Message) error {
		return deliveryBroken
	}); !errors.Is(err, deliveryBroken) {
		t.Fatalf("delivery failure was hidden: %v", err)
	}
	var delivered int
	if err := audit.deliver(t.Context(), func(_ context.Context, m mailbox.Message) error {
		var bundle auditBundle
		if m.Route != current.Account.Bech32 {
			return nil
		}
		if err := open(m.Body, m.ID, auditDeliveryPurpose, current.Recipient, 1, &bundle); err != nil {
			return err
		}
		if _, err := openAuditBundle(h.authority.card, current, bundle); err != nil {
			return err
		}
		delivered++
		return nil
	}); err != nil || delivered < 3 {
		t.Fatalf("durable encrypted deliveries did not retry: %d, %v", delivered, err)
	}
}

func TestAuditEvidenceSurvivesEarlierStatusDelivery(t *testing.T) {
	h := newHarness(t, 1)
	audit := newTestAudit(t, &h)
	if err := audit.rotate(h.host.Keys, 0, testAuditMembers(h.approvers[0])); err != nil {
		t.Fatal(err)
	}
	request := auditSession(t, &h, false)
	if _, err := h.host.recordHostState(request, lease.Observation{State: lease.Closed, Cause: "Expired"}); err != nil {
		t.Fatal(err)
	}
	checkDelivery := func(want string) {
		t.Helper()
		if err := h.host.queueSessionStatus(t.Context()); err != nil {
			t.Fatal(err)
		}
		sent := 0
		err := h.host.deliverSessionStatus(t.Context(), func(_ context.Context, message mailbox.Message) error {
			keys := h.authority.actors[message.Route]
			status, err := readSessionStatus(h.authority.card, keys, message)
			if err != nil || status.State != lease.Closed || status.ReceiptState != want {
				t.Fatalf("closed session status is %+v, error %v", status, err)
			}
			sent++
			return nil
		})
		if err != nil || sent != 2 {
			t.Fatalf("closed status deliveries: %d, %v", sent, err)
		}
	}
	checkDelivery("Pending")
	if err := h.host.maintainAudit(t.Context()); err != nil {
		t.Fatal(err)
	}
	checkDelivery("Available")
	entry, err := h.host.Journal.get(request)
	if err != nil || len(entry.Evidence.Receipts) != 1 || len(entry.Evidence.Targets) != 0 {
		t.Fatalf("receipt or status retention is incorrect: %v", err)
	}
}

func TestAuditRecoveryBlocksStaleIssuance(t *testing.T) {
	h := newHarness(t, 1)
	audit := newTestAudit(t, &h)
	current, removed := keys(t, 60), keys(t, 61)
	if err := audit.rotate(h.host.Keys, 0, testAuditMembers(current, removed)); err != nil {
		t.Fatal(err)
	}
	original, err := readAuditFile(audit.path)
	if err != nil {
		t.Fatal(err)
	}
	state, err := audit.recover(h.host.Keys)
	if err != nil {
		t.Fatal(err)
	}
	manager, err := qoreseal.NewEpochKeyManager(qoreseal.EpochKeyManagerOptions{
		ChainID: chain.NativeID, Purpose: auditPurpose(audit.group), History: []qoreseal.EpochKey{state.Key},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Rotate(); err != nil {
		t.Fatal(err)
	}
	key := manager.CurrentKey()
	defer clear(key.Key)
	if err := audit.stage(epochState{audit.group, key, testAuditMembers(current)}); err != nil {
		t.Fatal(err)
	}
	candidate, err := readAuditFile(audit.path + ".pending")
	if err != nil {
		t.Fatal(err)
	}
	marker := epochMarker{key.Epoch, sha256.Sum256(candidate)}
	if err := audit.db.Update(func(tx *bolt.Tx) error {
		return putAudit(tx.Bucket(auditEpochs), pendingEpoch, marker)
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(audit.path + ".pending"); err != nil {
		t.Fatal(err)
	}
	request := auditSession(t, &h, false)
	if _, err := h.host.recordHostState(request, lease.Observation{State: lease.Closed, Cause: "Expired"}); err != nil {
		t.Fatal(err)
	}
	if err := h.host.maintainAudit(t.Context()); err == nil {
		t.Fatal("stale epoch issued a receipt while rotation was incomplete")
	}
	item, err := h.host.Journal.get(request)
	if err != nil || item.Lease.State != lease.Closed || item.Evidence.ReceiptState != "Unavailable" || len(item.Evidence.Receipts) != 0 {
		t.Fatalf("incorrect state during receipt failure: %+v %v", item, err)
	}

	// Crash after replacing the file, before committing the new DB epoch.
	if err := os.WriteFile(audit.path, candidate, 0600); err != nil {
		t.Fatal(err)
	}
	audit.Clear()
	h.host.Audit = reopenTestAudit(t, h, audit.path)
	if err := h.host.maintainAudit(t.Context()); err != nil {
		t.Fatal(err)
	}
	item, err = h.host.Journal.get(request)
	if err != nil || len(item.Evidence.Receipts) != 1 || item.Evidence.ReceiptState != "Available" {
		t.Fatalf("unfulfilled receipt did not recover: %+v %v", item, err)
	}
	r, _ := exportAudit(t, h, item.Evidence.Receipts[0], current)
	if r.Epoch != 2 {
		t.Fatalf("receipt used stale epoch %d", r.Epoch)
	}
	if err := os.WriteFile(audit.path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.host.Audit.recover(h.host.Keys); err == nil {
		t.Fatal("rollback of the wrapped state was accepted")
	}
}

func TestAuditRejectsWrongGroupEpochAndSignature(t *testing.T) {
	h := newHarness(t, 1)
	audit := newTestAudit(t, &h)
	auditor := keys(t, 60)
	if err := audit.rotate(h.host.Keys, 0, testAuditMembers(auditor)); err != nil {
		t.Fatal(err)
	}
	request := auditSession(t, &h, false)
	if _, err := h.host.recordHostState(request, lease.Observation{State: lease.Closed, Cause: "Expired"}); err != nil {
		t.Fatal(err)
	}
	if err := h.host.maintainAudit(t.Context()); err != nil {
		t.Fatal(err)
	}
	item, err := h.host.Journal.get(request)
	if err != nil || len(item.Evidence.Receipts) != 1 {
		t.Fatalf("receipt not archived: %v", err)
	}
	receipt, bundle := exportAudit(t, h, item.Evidence.Receipts[0], auditor)
	state, err := audit.recover(h.host.Keys)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"group", "epoch", "signature", "index"} {
		t.Run(name, func(t *testing.T) {
			r, key, index, group, signer := receipt.Receipt, state.Key, receipt.Index, audit.group, h.host.Keys
			switch name {
			case "group":
				group[0] ^= 1
				r.Group = group
			case "epoch":
				key.Epoch++
				r.Epoch++
			case "signature":
				signer = auditor
			case "index":
				index++
			}
			sig, err := protocol.Sign(signer, receiptPurpose, r)
			if err != nil {
				t.Fatal(err)
			}
			data, err := protocol.Encode(signedReceipt{r, sig})
			if err != nil {
				t.Fatal(err)
			}
			batch, err := qoreseal.SealBatch(qoreseal.SealBatchArgs{EpochKey: key, Context: auditContext(group), BatchIndex: index, Data: data})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := openAuditBundle(h.authority.card, auditor, auditBundle{bundle.Distribution, batch.Blob}); err == nil {
				t.Fatal("accepted invalid receipt")
			}
		})
	}
}

func newTestAudit(t *testing.T, h *harness) *Audit {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state", "db")
	h.host.Journal, _ = journalAt(t, path)
	h.host.Audit = reopenTestAudit(t, *h, path+".audit.age")
	return h.host.Audit
}

func reopenTestAudit(t *testing.T, h harness, path string) *Audit {
	t.Helper()
	audit, err := NewAudit(h.host.Journal, path, h.authority.card.Details, []byte("audit fixture credential"))
	if err != nil {
		t.Fatal(err)
	}
	// Keep tests fast while exercising real age encryption and file recovery.
	audit.wrap.SetWorkFactor(10)
	t.Cleanup(audit.Clear)
	return audit
}

func testAuditMembers(auditors ...*identity.Keys) []qoreseal.Member {
	var members []qoreseal.Member
	for _, auditor := range auditors {
		members = append(members, qoreseal.Member{ID: auditor.Account.Bech32, Recipient: qoreseal.RecipientOf(auditor.Recipient)})
	}
	slices.SortFunc(members, func(a, b qoreseal.Member) int { return strings.Compare(a.ID, b.ID) })
	return members
}

func auditSession(t *testing.T, h *harness, paid bool) common.Hash {
	t.Helper()
	now := time.Now()
	request, _ := h.request(t, now)
	defer request.Clear()
	id, a := request.ID(), request.auth
	record := leaseRecord{ID: SessionReference(a.DoorID, id), Issued: now.Add(-time.Second).Unix(),
		Deadline: now.Add(time.Minute - time.Second).Unix(), State: lease.Reserved}
	actors := testAuditMembers(h.requester)
	reviewer := h.approvers[0]
	to := []sessionRecipient{{actors[0].ID, actors[0].Recipient}, {reviewer.Account.Bech32, qoreseal.RecipientOf(reviewer.Recipient)}}
	manifest, decision := common.Hash{10}, common.Hash{11}
	if paid {
		a.Offer, a.Service, a.Role = "offer", "private-status", ""
		to = to[:1]
		decision = manifest
		record.ConsumptionTx = common.Hash{12}
	}
	targets, err := h.host.sealSessionRecipients(record.ID, a, to)
	if err != nil {
		t.Fatal(err)
	}
	journal := h.host.Journal
	if err := journal.accept(id, manifest, mailbox.Message{Expires: now.Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	if ok, err := journal.decide(id, manifest, decision, Authorized, nil, &record, targets); err != nil || !ok {
		t.Fatalf("reserve test session: %v", err)
	}
	for _, state := range []lease.State{lease.Provisioning, lease.Ready, lease.Active} {
		if err := journal.updateLease(id, state, nil); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func exportAudit(t *testing.T, h harness, id common.Hash, auditor *identity.Keys) (AuditReceipt, auditBundle) {
	t.Helper()
	raw, err := ExportAuditReceipt(h.host.Journal.db, id, auditor.Account.Bech32)
	if err != nil {
		t.Fatal(err)
	}
	var bundle auditBundle
	if err := protocol.Decode(raw, &bundle); err != nil {
		t.Fatal(err)
	}
	r, err := openAuditBundle(h.authority.card, auditor, bundle)
	if err != nil || r.ID != id {
		t.Fatalf("verify archived receipt: %v", err)
	}
	return r, bundle
}
