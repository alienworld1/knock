package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"knock/internal/door"
	"knock/internal/identity"
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
	bolt "go.etcd.io/bbolt"
)

const (
	sessionStatusPurpose     = "knock-session-status-v1"
	sessionRecipientsPurpose = "knock-session-recipients-v1"
	statusInterval           = 10 * time.Second
	statusLifetime           = 30 * time.Second
	chainFreshness           = 2 * statusInterval
)

var sessionCache = []byte("verified-session-status-v1")

type sessionRecipient struct {
	Account string
	Key     qoreseal.SealRecipient
}

type sessionRecipients struct {
	Registry   common.Address
	DoorID     common.Hash
	RequestID  common.Hash
	Role       string
	Recipients []sessionRecipient
	Service    string `cbor:",omitempty"`
}

type leaseEvidence struct {
	Targets      []byte
	Revision     uint64
	Published    uint64
	Changed      int64
	ChainAt      int64
	Degraded     bool
	RevokedAt    int64
	RevokedBlock common.Hash
	ClosedAt     int64
	Cause        string
	Outbox       []mailbox.Message
	ActiveAt     int64
	EndedAt      int64
	Closures     []closureEvidence
	Receipts     []common.Hash
	ReceiptState string
}

func (e *leaseEvidence) touch(now int64) {
	e.Revision++
	e.Changed = now
	e.Outbox = nil
}

type SessionStatus struct {
	Version      uint64         `json:"version"`
	Registry     common.Address `json:"registry"`
	DoorID       common.Hash    `json:"doorId"`
	RequestID    common.Hash    `json:"requestId"`
	Session      common.Hash    `json:"sessionId"`
	Door         string         `json:"door"`
	Role         string         `json:"role"`
	Service      string         `json:"service,omitempty" cbor:",omitempty"`
	State        lease.State    `json:"state"`
	Revision     uint64         `json:"revision"`
	Observed     int64          `json:"observed"`
	Deadline     int64          `json:"deadline"`
	Issued       int64          `json:"issued,omitempty" cbor:",omitempty"`
	ChainAt      int64          `json:"chainChecked,omitempty"`
	Degraded     bool           `json:"chainDegraded"`
	RevokedAt    int64          `json:"revokedAt,omitempty"`
	RevokedBlock common.Hash    `json:"revokedBlock"`
	ClosedAt     int64          `json:"closedAt,omitempty"`
	Cause        string         `json:"cause,omitempty"`
	ReceiptState string         `json:"receiptState,omitempty" cbor:",omitempty"`
}

func (s SessionStatus) Fresh(now time.Time) bool {
	age := now.Sub(time.Unix(s.Observed, 0))
	return age >= -5*time.Second && age <= 2*statusInterval && (s.Deadline > now.Unix() ||
		s.State == lease.Closed || s.State == lease.Closing || s.State == lease.CleanupIncomplete)
}

func (s SessionStatus) MonitoringDegraded(now time.Time) bool {
	age := now.Sub(time.Unix(s.ChainAt, 0))
	return s.Degraded || age > chainFreshness || age < -5*time.Second
}

func (s SessionStatus) withinRetention(now time.Time) bool {
	age := now.Sub(time.Unix(s.Observed, 0))
	return age >= -5*time.Second && age < mailbox.Retention
}

type signedSessionStatus struct {
	Record    SessionStatus
	Signing   []byte
	Signature qoresign.MessageSignature
}

func (h Host) sealSessionRecipients(id common.Hash, a authorization, recipients []sessionRecipient) ([]byte, error) {
	targets := sessionRecipients{Registry: a.Registry, DoorID: a.DoorID, RequestID: a.RequestID, Role: a.Role, Recipients: recipients}
	if a.Offer != "" {
		targets.Service = a.Service
	}
	return seal(targets, id, sessionRecipientsPurpose, qoreseal.RecipientOf(h.Keys.Recipient))
}

func sessionStatusID(s SessionStatus, route string) common.Hash {
	return recordID(sessionStatusPurpose, s.Session, s.DoorID, route+"/"+strconv.FormatUint(s.Revision, 10))
}

func (h Host) queueSessionStatus(ctx context.Context) error {
	sessions, err := h.Journal.sessions()
	if err != nil {
		return err
	}
	var failure error
	for _, session := range sessions {
		e := session.Evidence
		if e == nil || e.Published == e.Revision || len(e.Outbox) != 0 {
			continue
		}
		if ctx.Err() != nil {
			return failure
		}
		if session.Record.State == lease.Closed && time.Since(time.Unix(e.Changed, 0)) >= mailbox.Retention {
			_, err := h.Journal.editLease(session.Request, func(item *entry) (bool, error) {
				item.Evidence.Published = item.Evidence.Revision
				if h.canDiscardStatusTargets(item.Evidence) {
					item.Evidence.Targets = nil
				}
				return true, nil
			})
			if err != nil {
				return err
			}
			continue
		}
		if err := h.buildStatusNotice(session); err != nil {
			failure = errors.Join(failure, err)
		}
	}
	return failure
}

func (h Host) buildStatusNotice(session journalSession) error {
	record, e := session.Record, session.Evidence
	var target sessionRecipients
	if err := open(e.Targets, record.ID, sessionRecipientsPurpose, h.Keys.Recipient, 1, &target); err != nil {
		return err
	}
	if len(target.Recipients) == 0 || len(target.Recipients) > 3 || target.RequestID != session.Request ||
		SessionReference(target.DoorID, target.RequestID) != record.ID {
		return ErrInvalid
	}
	s := SessionStatus{
		Version: 1, Registry: target.Registry, DoorID: target.DoorID, RequestID: target.RequestID, Session: record.ID,
		Door: h.Keys.Account.Bech32, Role: target.Role, Service: target.Service, State: record.State, Revision: e.Revision, Observed: e.Changed,
		Deadline: record.Deadline, Issued: record.Issued, ChainAt: e.ChainAt, Degraded: e.Degraded, RevokedAt: e.RevokedAt,
		RevokedBlock: e.RevokedBlock, ClosedAt: e.ClosedAt, Cause: e.Cause,
	}
	if h.Audit != nil && len(e.Closures) != 0 {
		s.ReceiptState = e.ReceiptState
		if s.ReceiptState == "" || (s.ReceiptState == "Available" && len(e.Receipts) < len(e.Closures)) {
			s.ReceiptState = "Pending"
		}
	}
	signature, err := protocol.Sign(h.Keys, sessionStatusPurpose, s)
	if err != nil {
		return err
	}
	sealed := signedSessionStatus{s, h.Keys.Signing.PublicKey, signature}
	lifetime := statusLifetime
	if s.State == lease.Closed {
		lifetime = mailbox.Retention
	}
	expires := time.Now().Add(lifetime - 5*time.Second).Unix()
	outbox := make([]mailbox.Message, 0, len(target.Recipients))
	for _, recipient := range target.Recipients {
		id := sessionStatusID(s, recipient.Account)
		body, err := seal(sealed, id, sessionStatusPurpose, recipient.Key)
		if err != nil {
			return err
		}
		outbox = append(outbox, mailbox.Message{Route: recipient.Account, ID: id, Expires: expires, Body: body})
	}
	_, err = h.Journal.editLease(session.Request, func(item *entry) (bool, error) {
		if item.Evidence == nil || item.Evidence.Revision != s.Revision || len(item.Evidence.Outbox) != 0 {
			return false, nil
		}
		item.Evidence.Outbox = outbox
		return true, nil
	})
	return err
}

// Receipt issuance uses the same sealed targets as session status. Keep
// them until every recorded terminal observation has an archived receipt.
func (h Host) canDiscardStatusTargets(e *leaseEvidence) bool {
	return h.Audit == nil || len(e.Receipts) == len(e.Closures)
}

func (h Host) deliverSessionStatus(ctx context.Context, send func(context.Context, mailbox.Message) error) error {
	sessions, err := h.Journal.sessions()
	if err != nil {
		return err
	}
	priority := func(s journalSession) int {
		switch s.Record.State {
		case lease.Closed, lease.Closing, lease.CleanupIncomplete:
			return 0
		default:
			return 1
		}
	}
	slices.SortStableFunc(sessions, func(a, b journalSession) int { return priority(a) - priority(b) })
	var failure error
	for _, item := range sessions {
		e := item.Evidence
		if e == nil || len(e.Outbox) == 0 {
			continue
		}
		var remaining []mailbox.Message
		for _, notice := range e.Outbox {
			if notice.Expires <= time.Now().Unix() {
				continue
			}
			call, cancel := context.WithTimeout(ctx, 4*time.Second)
			err := send(call, notice)
			cancel()
			if err != nil {
				failure = err
				remaining = append(remaining, notice)
			}
		}
		// If delivery expired, permit the monitor to seal a fresh terminal notice
		// with a new ID. This also works after an ambiguous prior delivery.
		expired := e.Outbox[0].Expires <= time.Now().Unix()
		_, err := h.Journal.editLease(item.Request, func(current *entry) (bool, error) {
			active := current.Evidence
			if active == nil || active.Revision != e.Revision {
				return false, nil
			}
			active.Outbox = remaining
			if len(remaining) == 0 {
				if expired && current.Lease.State == lease.Closed && time.Since(time.Unix(active.Changed, 0)) < mailbox.Retention {
					active.Revision++
				} else {
					active.Published = e.Revision
					if current.Lease.State == lease.Closed && h.canDiscardStatusTargets(active) {
						active.Targets = nil
					}
				}
			}
			return true, nil
		})
		if err != nil {
			return errors.Join(failure, err)
		}
	}
	return failure
}

func readSessionStatus(card door.Card, keys *identity.Keys, message mailbox.Message) (SessionStatus, error) {
	var signed signedSessionStatus
	if message.Route != keys.Account.Bech32 ||
		open(message.Body, message.ID, sessionStatusPurpose, keys.Recipient, 1, &signed) != nil {
		return SessionStatus{}, ErrInvalid
	}
	s, d := signed.Record, card.Details
	if s.Version != 1 || s.Door != d.Account || s.DoorID != d.DoorID || s.Registry != d.Registry.Address ||
		s.Revision == 0 || !validReceiptState(s.ReceiptState) || s.Observed <= 0 || s.Deadline <= 0 || s.RequestID == (common.Hash{}) ||
		s.Session != SessionReference(s.DoorID, s.RequestID) || message.ID != sessionStatusID(s, message.Route) ||
		(s.Issued != 0 && (s.Issued < 0 || s.Issued >= s.Deadline || s.Issued > s.Observed)) ||
		!validSessionScope(s.Role, s.Service) || sha256.Sum256(signed.Signing) != d.SigningKey || card.VerifySigner(signed.Signing) != nil ||
		(s.RevokedAt > 0) != (s.RevokedBlock != (common.Hash{})) || (s.State == lease.Closed) != (s.ClosedAt > 0) ||
		protocol.Verify(s.Door, signed.Signing, sessionStatusPurpose, s, signed.Signature) != nil {
		return SessionStatus{}, ErrInvalid
	}
	switch s.State {
	case lease.Reserved, lease.Provisioning, lease.Ready, lease.Active, lease.Closing, lease.CleanupIncomplete, lease.Closed:
		return s, nil
	default:
		return SessionStatus{}, ErrInvalid
	}
}

func validReceiptState(state string) bool {
	switch state {
	case "", "Pending", "Unavailable", "Available":
		return true
	default:
		return false
	}
}

func validSessionScope(role, service string) bool {
	if service != "" {
		return role == "" && door.IsAlias(service)
	}
	return role == "logs" || role == "maintenance"
}

// LoadSessionStatus stores only sealed, verified revisions. It returns the
// last verified observations even when the Mailbox is unavailable.
func LoadSessionStatus(ctx context.Context, db *bolt.DB, relay *mailbox.Client, card door.Card, keys *identity.Keys) ([]SessionStatus, error) {
	latest := make(map[common.Hash]SessionStatus)
	now := time.Now()
	if err := db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(sessionCache)
		if bucket == nil {
			return nil
		}
		prefix := card.Details.DoorID[:]
		c := bucket.Cursor()
		var expired [][]byte
		for k, raw := c.Seek(prefix); bytes.HasPrefix(k, prefix); k, raw = c.Next() {
			var message mailbox.Message
			if err := json.Unmarshal(raw, &message); err != nil {
				return err
			}
			if value, err := readSessionStatus(card, keys, message); err == nil {
				if value.withinRetention(now) {
					latest[value.Session] = value
				} else {
					expired = append(expired, bytes.Clone(k))
				}
			}
		}
		for _, key := range expired {
			if err := bucket.Delete(key); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	var inbox []mailbox.Message
	var relayErr error
	if relay != nil {
		inbox, relayErr = relay.Inbox(ctx)
	}
	for _, message := range inbox {
		value, err := readSessionStatus(card, keys, message)
		if err != nil || message.Expires <= now.Unix() || !value.withinRetention(now) {
			continue
		}
		if prev := latest[value.Session]; value.Revision > prev.Revision &&
			(prev.State != lease.Closed || value.State == lease.Closed) {
			raw, err := json.Marshal(message)
			if err != nil {
				return nil, err
			}
			key := append(bytes.Clone(value.DoorID[:]), value.Session[:]...)
			if err := db.Update(func(tx *bolt.Tx) error {
				bucket, err := tx.CreateBucketIfNotExists(sessionCache)
				if err != nil {
					return err
				}
				if bucket.Get(key) == nil && bucket.Stats().KeyN >= maxJournal {
					return fmt.Errorf("local session status store is full")
				}
				return bucket.Put(key, raw)
			}); err != nil {
				return nil, err
			}
			latest[value.Session] = value
		}
		call, cancel := context.WithTimeout(ctx, time.Second)
		_ = relay.Ack(call, message.ID)
		cancel()
	}
	results := make([]SessionStatus, 0, len(latest))
	for _, status := range latest {
		results = append(results, status)
	}
	return results, relayErr
}
