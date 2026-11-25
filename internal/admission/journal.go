package admission

import (
	"encoding/json"
	"errors"
	"time"

	"knock/internal/lease"
	"knock/internal/mailbox"

	"github.com/ethereum/go-ethereum/common"
	bolt "go.etcd.io/bbolt"
)

var journalName = []byte("admission-v1")

const maxJournal = 4096

type Journal struct{ db *bolt.DB }

type entry struct {
	Manifest common.Hash
	Decision common.Hash
	Deadline int64
	Outcome  Outcome
	Delivery *mailbox.Message
	Notice   *mailbox.Message
	Lease    *leaseRecord
	Evidence *leaseEvidence
}

func NewJournal(db *bolt.DB) (*Journal, error) {
	err := db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(journalName)
		return err
	})
	return &Journal{db}, err
}

func writeEntry(b *bolt.Bucket, id common.Hash, item entry) error {
	data, err := json.Marshal(item)
	if err != nil {
		return err
	}
	return b.Put(id[:], data)
}

func loadEntry(b *bolt.Bucket, id common.Hash) (entry, error) {
	var item entry
	raw := b.Get(id[:])
	if raw == nil {
		return item, ErrPending
	}
	return item, json.Unmarshal(raw, &item)
}

func (j *Journal) accept(id, digest common.Hash, message mailbox.Message) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalName)
		prior, err := loadEntry(b, id)
		if err == nil {
			if prior.Manifest != digest {
				return ErrInvalid
			}
			return nil
		}
		if !errors.Is(err, ErrPending) {
			return err
		}
		if message.Expires <= time.Now().Unix() {
			return ErrExpired
		}
		if b.Stats().KeyN >= maxJournal {
			return errors.New("Door admission journal is full")
		}
		return writeEntry(b, id, entry{Manifest: digest, Deadline: message.Expires, Outcome: Pending, Delivery: &message})
	})
}

func (j *Journal) get(id common.Hash) (entry, error) {
	var item entry
	err := j.db.View(func(tx *bolt.Tx) error {
		var err error
		item, err = loadEntry(tx.Bucket(journalName), id)
		return err
	})
	return item, err
}

type leaseRecord struct {
	ID       common.Hash
	Issued   int64
	Deadline int64
	State    lease.State
}

// decide durably consumes authorization before the host can touch resources.
func (j *Journal) decide(id, manifest, decision common.Hash, outcome Outcome, notice *mailbox.Message, session *leaseRecord, targets []byte) (bool, error) {
	var accepted bool
	err := j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalName)
		item, err := loadEntry(b, id)
		if err != nil {
			return err
		}
		if item.Manifest != manifest {
			return ErrInvalid
		}
		if item.Outcome != Pending {
			if item.Decision == decision && item.Outcome == outcome && item.Outcome != Expired {
				return nil
			}
			return ErrInvalid
		}
		if time.Now().Unix() >= item.Deadline {
			return ErrExpired
		}
		item.Outcome, item.Decision, item.Delivery, item.Notice, item.Lease = outcome, decision, nil, notice, session
		if len(targets) != 0 && session != nil {
			item.Evidence = &leaseEvidence{Targets: targets, Revision: 1, Changed: session.Issued}
		}
		accepted = true
		return writeEntry(b, id, item)
	})
	return accepted, err
}

func (j *Journal) updateLease(id common.Hash, state lease.State, notice *mailbox.Message) error {
	_, err := j.editLease(id, func(item *entry) (bool, error) {
		changed := item.advance(state, time.Now().Unix())
		if !changed && (state == lease.Provisioning || state == lease.Ready) {
			return false, errors.New("the SSH session is no longer available for provisioning")
		}
		if notice != nil {
			item.Notice = notice
			changed = true
		}
		return changed, nil
	})
	return err
}

func (item *entry) advance(next lease.State, now int64) bool {
	current := item.Lease.State
	if current == next || current == lease.Closed {
		return false
	}
	switch next {
	case lease.Provisioning:
		if current != lease.Reserved {
			return false
		}
	case lease.Ready:
		if current != lease.Provisioning {
			return false
		}
	case lease.Active:
		if current != lease.Ready {
			return false
		}
	case lease.Closing:
		if current == lease.CleanupIncomplete {
			return false
		}
	case lease.Closed, lease.CleanupIncomplete:
	default:
		return false
	}
	item.Lease.State = next
	if next == lease.Closing || next == lease.Closed || next == lease.CleanupIncomplete {
		if item.Notice != nil && item.Notice.ID == connectionID(item.Lease.ID) {
			item.Notice = nil
		}
	}
	if evidence := item.Evidence; evidence != nil {
		if next == lease.Closed {
			evidence.ClosedAt = now
		}
		evidence.touch(now)
	}
	return true
}

func (j *Journal) editLease(id common.Hash, edit func(*entry) (bool, error)) (bool, error) {
	var changed bool
	err := j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalName)
		item, err := loadEntry(b, id)
		if err != nil {
			return err
		}
		if item.Lease == nil {
			return ErrInvalid
		}
		changed, err = edit(&item)
		if err != nil || !changed {
			return err
		}
		return writeEntry(b, id, item)
	})
	return changed, err
}

type journalSession struct {
	Request  common.Hash
	Record   leaseRecord
	Evidence *leaseEvidence
}

func (j *Journal) sessions() ([]journalSession, error) {
	var sessions []journalSession
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(journalName).ForEach(func(key, raw []byte) error {
			var item entry
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			if item.Lease != nil {
				sessions = append(sessions, journalSession{common.Hash(key), *item.Lease, item.Evidence})
			}
			return nil
		})
	})
	return sessions, err
}

func (j *Journal) expire(now int64) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalName)
		c := b.Cursor()
		updates := make(map[common.Hash]entry)
		for key, raw := c.First(); key != nil; key, raw = c.Next() {
			var item entry
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			// Preserve the terminal tombstone across wall-clock corrections.
			if item.Deadline <= now && item.Outcome == Pending {
				item.Outcome, item.Delivery = Expired, nil
				updates[common.Hash(key)] = item
			}
			if item.Notice != nil && item.Notice.Expires <= now {
				item.Notice = nil
				updates[common.Hash(key)] = item
			}
		}
		for id, item := range updates {
			if err := writeEntry(b, id, item); err != nil {
				return err
			}
		}
		return nil
	})
}

type queuedNotice struct {
	request common.Hash
	message mailbox.Message
}

func (j *Journal) notices() ([]queuedNotice, error) {
	var pending []queuedNotice
	err := j.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(journalName).ForEach(func(key, raw []byte) error {
			if len(pending) >= mailbox.PageSize {
				return nil
			}
			var item entry
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			if item.Notice != nil && (item.Lease == nil || item.Notice.ID != connectionID(item.Lease.ID)) {
				pending = append(pending, queuedNotice{common.Hash(key), *item.Notice})
			}
			return nil
		})
	})
	return pending, err
}

func (j *Journal) delivered(id, delivery common.Hash) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalName)
		item, err := loadEntry(b, id)
		if err != nil {
			return err
		}
		if item.Notice == nil || item.Notice.ID != delivery {
			return nil
		}
		item.Notice = nil
		return writeEntry(b, id, item)
	})
}
