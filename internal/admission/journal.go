package admission

import (
	"bytes"
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
func (j *Journal) decide(id, manifest, decision common.Hash, outcome Outcome, notice *mailbox.Message, session *leaseRecord) (bool, error) {
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
		accepted = true
		return writeEntry(b, id, item)
	})
	return accepted, err
}

func (j *Journal) updateLease(id common.Hash, state lease.State, notice *mailbox.Message) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalName)
		item, err := loadEntry(b, id)
		if err != nil {
			return err
		}
		if item.Lease == nil {
			return ErrInvalid
		}
		if (state == lease.Provisioning && item.Lease.State != lease.Reserved) ||
			(state == lease.Ready && item.Lease.State != lease.Provisioning) {
			return errors.New("the SSH session is no longer available for provisioning")
		}
		if item.Lease.State != lease.Closed {
			item.Lease.State = state
		}
		item.Notice = notice
		return writeEntry(b, id, item)
	})
}

func (j *Journal) observeLease(session common.Hash, state lease.State) (bool, error) {
	var changed bool
	err := j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalName)
		var id common.Hash
		var item entry
		if err := b.ForEach(func(key, raw []byte) error {
			if id != (common.Hash{}) {
				return nil
			}
			var candidate entry
			if err := json.Unmarshal(raw, &candidate); err != nil {
				return err
			}
			if candidate.Lease != nil && candidate.Lease.ID == session {
				id, item = common.Hash(key), candidate
			}
			return nil
		}); err != nil {
			return err
		}
		if id == (common.Hash{}) || item.Lease.State == state || item.Lease.State == lease.Closed {
			return nil
		}
		if state == lease.Active && item.Lease.State != lease.Ready {
			return nil
		}
		item.Lease.State = state
		if (state == lease.Closed || state == lease.CleanupIncomplete) &&
			item.Notice != nil && item.Notice.ID == connectionID(session) {
			item.Notice = nil
		}
		changed = true
		return writeEntry(b, id, item)
	})
	return changed, err
}

func (j *Journal) expire(now int64) error {
	return j.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(journalName)
		c := b.Cursor()
		var remove [][]byte
		updates := make(map[common.Hash]entry)
		for key, raw := c.First(); key != nil; key, raw = c.Next() {
			var item entry
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			if item.Lease == nil && now >= item.Deadline+int64(time.Hour/time.Second) {
				remove = append(remove, bytes.Clone(key))
				continue
			}
			if item.Deadline <= now && item.Outcome == Pending {
				item.Outcome, item.Delivery = Expired, nil
				updates[common.Hash(key)] = item
			}
			if item.Notice != nil && item.Notice.Expires <= now {
				item.Notice = nil
				updates[common.Hash(key)] = item
			}
		}
		for _, key := range remove {
			if err := b.Delete(key); err != nil {
				return err
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
