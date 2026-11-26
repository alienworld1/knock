package admission

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
	bolt "go.etcd.io/bbolt"

	"knock/internal/door"
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"
)

const receiptPurpose = "knock-receipt-v1"

type closureEvidence struct {
	State    lease.State
	Observed int64
	Cause    string
}

// Receipt records the Door's observations and the authorization for one session.
type Receipt struct {
	Group                 common.Hash
	Epoch                 uint64
	Index                 uint64
	Door                  string
	Registry              common.Address
	DoorID                common.Hash
	Session               common.Hash
	Request               common.Hash
	Requester             string
	Approver              string
	Authorization         common.Hash
	Purchase              common.Hash
	ConsumptionTx         common.Hash
	Role                  string
	Service               string
	RequestedSeconds      uint64
	IssuedAt              int64
	ActiveObservedAt      int64
	TerminationObservedAt int64
	ActualSeconds         uint64
	Cause                 string
	Cleanup               lease.State
	CleanupObservedAt     int64
	RevocationBlock       common.Hash
	Corrects              common.Hash
}

type signedReceipt struct {
	Record    Receipt
	Signature qoresign.MessageSignature
}

type AuditReceipt struct {
	ID common.Hash
	Receipt
}

type auditBundle struct {
	Distribution signedDistribution
	Blob         []byte
}

type epochArchive struct {
	Distribution signedDistribution
	Members      []string
}

type receiptArchive struct {
	Epoch uint64
	Blob  []byte
}

func auditEpochKey(epoch uint64) []byte {
	return binary.BigEndian.AppendUint64(nil, epoch)
}

func auditDeliveries(bundle auditBundle, members []qoreseal.Member) ([]mailbox.Message, error) {
	expires := time.Now().Add(mailbox.Retention - 10*time.Second).Unix()
	messages := make([]mailbox.Message, 0, len(members))
	for _, member := range members {
		var id common.Hash
		rand.Read(id[:])
		body, err := seal(bundle, id, auditDeliveryPurpose, member.Recipient)
		if err != nil {
			return nil, err
		}
		messages = append(messages, mailbox.Message{ID: id, Route: member.ID, Expires: expires, Body: body})
	}
	return messages, nil
}

func queueAudit(tx *bolt.Tx, messages []mailbox.Message) error {
	b := tx.Bucket(auditOutbox)
	for _, message := range messages {
		if err := putAudit(b, message.ID[:], message); err != nil {
			return err
		}
	}
	return nil
}

func (a *Audit) deliver(ctx context.Context, send func(context.Context, mailbox.Message) error) error {
	var messages []mailbox.Message
	err := a.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(auditOutbox).Cursor()
		for k, v := c.First(); k != nil && len(messages) < mailbox.PageSize; k, v = c.Next() {
			var message mailbox.Message
			if err := protocol.Decode(v, &message); err != nil {
				return err
			}
			messages = append(messages, message)
		}
		return nil
	})
	if err != nil {
		return err
	}
	var failed error
	for _, message := range messages {
		if message.Expires > time.Now().Unix() {
			if err := send(ctx, message); err != nil {
				failed = errors.Join(failed, err)
				continue
			}
		}
		if err := a.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(auditOutbox).Delete(message.ID[:]) }); err != nil {
			return errors.Join(failed, err)
		}
	}
	return failed
}

// MaintainAudit retries receipt and delivery work independently of host enforcement.
func (h Host) MaintainAudit(ctx context.Context, relay *mailbox.Client) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	var epochFailed, deliveryFailed, jobFailed bool
	for ctx.Err() == nil {
		h.Audit.mu.Lock()
		_, recoveryErr := h.Audit.recover(h.Keys)
		h.Audit.mu.Unlock()
		failed := recoveryErr != nil && !errors.Is(recoveryErr, errAuditUnconfigured)
		if failed != epochFailed && h.Progress != nil {
			if failed {
				h.Progress("Audit epoch unavailable. Receipt issuance paused.")
			} else {
				h.Progress("Audit epoch recovered")
			}
		}
		epochFailed = failed
		if err := h.maintainAudit(ctx); err != nil && h.Progress != nil && !epochFailed && !errors.Is(err, errAuditUnconfigured) && !errors.Is(err, errAuditNoMembers) {
			// Per-session failures are also reflected in signed status.
			if !jobFailed {
				h.Progress("Receipt preparation failed. Retrying.")
			}
			jobFailed = true
		} else {
			jobFailed = false
		}
		err := h.Audit.deliver(ctx, relay.Send)
		if (err != nil) != deliveryFailed && h.Progress != nil && ctx.Err() == nil {
			if err != nil {
				h.Progress("Receipt delivery unavailable. Retrying.")
			} else {
				h.Progress("Receipt delivery resumed")
			}
		}
		deliveryFailed = err != nil
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (h Host) maintainAudit(ctx context.Context) error {
	sessions, err := h.Journal.sessions()
	if err != nil {
		return err
	}
	var failed error
	for _, session := range sessions {
		if ctx.Err() != nil {
			break
		}
		e := session.Evidence
		if e == nil || len(e.Receipts) >= len(e.Closures) {
			continue
		}
		for next := len(e.Receipts); next < len(e.Closures); next++ {
			if err := h.issueReceipt(session.Request, next); err != nil {
				failed = errors.Join(failed, err, h.recordAuditFailure(session.Request))
				break
			}
		}
	}
	return failed
}

func (h Host) recordAuditFailure(request common.Hash) error {
	changed, err := h.Journal.editLease(request, func(item *entry) (bool, error) {
		e := item.Evidence
		if e.ReceiptState == "Unavailable" {
			return false, nil
		}
		e.ReceiptState = "Unavailable"
		e.touch(time.Now().Unix())
		return true, nil
	})
	if changed && h.Progress != nil {
		h.Progress("Receipt unavailable for request " + request.Hex() + ". Retrying.")
	}
	return err
}

func (h Host) issueReceipt(request common.Hash, next int) error {
	a := h.Audit
	a.mu.Lock()
	defer a.mu.Unlock()
	item, err := h.Journal.get(request)
	if err != nil {
		return err
	}
	e := item.Evidence
	if next != len(e.Receipts) || next >= len(e.Closures) {
		return ErrInvalid
	}
	state, err := a.recover(h.Keys)
	if err != nil {
		return err
	}
	if len(state.Members) == 0 {
		return errAuditNoMembers
	}
	var distribution epochArchive
	var index uint64
	// Reserve the index durably before it can be used by the codec.
	err = a.db.Update(func(tx *bolt.Tx) error {
		ok, err := readAudit(tx.Bucket(auditEpochs), auditEpochKey(state.Key.Epoch), &distribution)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("audit epoch distribution is missing")
		}
		index, err = tx.Bucket(auditArchive).NextSequence()
		return err
	})
	if err != nil {
		return err
	}
	if index == 0 {
		return errors.New("receipt index exhausted")
	}
	r, err := h.receipt(request, item, state.Key.Epoch, index, next)
	if err != nil {
		return err
	}
	sig, err := protocol.Sign(h.Keys, receiptPurpose, r)
	if err != nil {
		return err
	}
	raw, err := protocol.Encode(signedReceipt{r, sig})
	if err != nil {
		return err
	}
	defer clear(raw)
	batch, err := qoreseal.SealBatch(qoreseal.SealBatchArgs{EpochKey: state.Key, Context: auditContext(a.group), BatchIndex: index, Data: raw})
	if err != nil {
		return err
	}
	id := sha256.Sum256(batch.Blob)
	outbox, err := auditDeliveries(auditBundle{distribution.Distribution, batch.Blob}, state.Members)
	if err != nil {
		return err
	}
	err = a.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalName)
		current, err := loadEntry(b, request)
		if err != nil {
			return err
		}
		e := current.Evidence
		if len(e.Receipts) != next || e.Closures[next] != item.Evidence.Closures[next] {
			return ErrInvalid
		}
		archive := tx.Bucket(auditArchive)
		if archive.Get(id[:]) != nil {
			return errors.New("receipt reference already exists")
		}
		if err := putAudit(archive, id[:], receiptArchive{state.Key.Epoch, batch.Blob}); err != nil {
			return err
		}
		if err := queueAudit(tx, outbox); err != nil {
			return err
		}
		e.Receipts = append(e.Receipts, id)
		e.ReceiptState = "Available"
		if len(e.Receipts) < len(e.Closures) {
			e.ReceiptState = "Pending"
		}
		e.touch(time.Now().Unix())
		return writeEntry(b, request, current)
	})
	if err == nil {
		h.progress(r.Session, "Receipt available · "+common.Hash(id).Hex())
	}
	return err
}

func (h Host) receipt(request common.Hash, item entry, epoch, index uint64, next int) (Receipt, error) {
	var r Receipt
	e, session := item.Evidence, item.Lease
	var targets sessionRecipients
	if err := open(e.Targets, session.ID, sessionRecipientsPurpose, h.Keys.Recipient, 1, &targets); err != nil {
		return r, err
	}
	if targets.RequestID != request || SessionReference(targets.DoorID, request) != session.ID ||
		len(targets.Recipients) == 0 || !validSessionScope(targets.Role, targets.Service) {
		return r, ErrInvalid
	}
	closure := e.Closures[next]
	ended := max(session.Issued, e.EndedAt)
	active := e.ActiveAt
	var duration uint64
	if active != 0 {
		duration = uint64(max(0, min(ended, session.Deadline)-active))
	}
	r = Receipt{
		Group: h.Audit.group, Epoch: epoch, Index: index, Door: h.Keys.Account.Bech32,
		Registry: targets.Registry, DoorID: targets.DoorID, Session: session.ID, Request: request,
		Requester: targets.Recipients[0].Account, Authorization: item.Decision,
		Role: targets.Role, Service: targets.Service, RequestedSeconds: uint64(session.Deadline - session.Issued),
		IssuedAt: session.Issued, ActiveObservedAt: active, TerminationObservedAt: ended, ActualSeconds: duration,
		Cause: closure.Cause, Cleanup: closure.State, CleanupObservedAt: max(ended, closure.Observed), RevocationBlock: e.RevokedBlock,
	}
	if r.Service != "" {
		r.Purchase, r.ConsumptionTx = item.Manifest, session.ConsumptionTx
	} else if len(targets.Recipients) >= 2 {
		r.Approver = targets.Recipients[1].Account
	}
	if next != 0 {
		r.Corrects = e.Receipts[next-1]
	}
	return r, r.validate(targets.DoorID, targets.Registry, h.Keys.Account.Bech32)
}

func (r Receipt) validate(doorID common.Hash, registry common.Address, account string) error {
	_, requesterErr := door.ParseAccount(r.Requester)
	_, approverErr := door.ParseAccount(r.Approver)
	if r.DoorID != doorID || r.Registry != registry || r.Door != account || r.Index == 0 || r.Epoch == 0 ||
		r.Request == (common.Hash{}) || r.Session != SessionReference(r.DoorID, r.Request) || r.Authorization == (common.Hash{}) ||
		requesterErr != nil || !validSessionScope(r.Role, r.Service) || r.RequestedSeconds == 0 || r.RequestedSeconds > 3600 ||
		r.IssuedAt <= 0 || r.TerminationObservedAt < r.IssuedAt || r.CleanupObservedAt < r.TerminationObservedAt ||
		r.Cause == "" || (r.Cleanup != lease.Closed && r.Cleanup != lease.CleanupIncomplete) ||
		(r.Corrects != (common.Hash{}) && r.Cleanup != lease.Closed) {
		return ErrInvalid
	}
	if r.Service != "" {
		if r.Approver != "" || r.Purchase == (common.Hash{}) || r.Purchase != r.Authorization {
			return ErrInvalid
		}
	} else if approverErr != nil || r.Purchase != (common.Hash{}) || r.ConsumptionTx != (common.Hash{}) {
		return ErrInvalid
	}
	if r.ActiveObservedAt == 0 {
		if r.ActualSeconds != 0 {
			return ErrInvalid
		}
	} else if r.ActiveObservedAt < r.IssuedAt || r.ActiveObservedAt > r.TerminationObservedAt ||
		r.ActualSeconds != uint64(max(0, min(r.TerminationObservedAt, r.IssuedAt+int64(r.RequestedSeconds))-r.ActiveObservedAt)) {
		return ErrInvalid
	}
	return nil
}
