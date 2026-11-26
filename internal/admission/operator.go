package admission

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"knock/internal/identity"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	bolt "go.etcd.io/bbolt"
)

var operatorBucket = []byte("operator-decisions-v1")

type operatorDecision struct {
	Outcome   Outcome
	Manifest  common.Hash
	Message   mailbox.Message
	Delivered bool `json:",omitempty"`
}

// SendDecision saves the sealed decision before sending it. A retry uses the
// original ciphertext, even if the previous Mailbox response was lost.
func SendDecision(ctx context.Context, db *bolt.DB, authority Authority, relay *mailbox.Client,
	keys *identity.Keys, review Review, outcome Outcome,
) error {
	id := review.Summary().ID
	manifest, err := protocol.Digest(review.signed)
	if err != nil {
		return err
	}
	stored, err := operatorPrior(db, id)
	if err != nil {
		return err
	}
	if stored.Message.ID == (common.Hash{}) {
		message, err := review.Decision(ctx, authority, keys, outcome)
		if err != nil {
			return err
		}
		stored = operatorDecision{Outcome: outcome, Manifest: manifest, Message: message}
		if err := db.Update(func(tx *bolt.Tx) error {
			b, err := tx.CreateBucketIfNotExists(operatorBucket)
			if err != nil {
				return err
			}
			c := b.Cursor()
			var expired []common.Hash
			for key, raw := c.First(); key != nil; key, raw = c.Next() {
				var previous operatorDecision
				if err := json.Unmarshal(raw, &previous); err != nil {
					return err
				}
				if previous.Message.Expires <= time.Now().Unix() {
					expired = append(expired, common.Hash(key))
				}
			}
			for _, key := range expired {
				if err := b.Delete(key[:]); err != nil {
					return err
				}
			}
			if b.Get(id[:]) != nil {
				return errors.New("another decision was saved. Retry the original decision.")
			}
			if b.Stats().KeyN >= maxJournal {
				return errors.New("operator decision store is full")
			}
			raw, err := json.Marshal(stored)
			if err != nil {
				return err
			}
			return b.Put(id[:], raw)
		}); err != nil {
			return err
		}
	}
	if stored.Manifest != manifest || stored.Outcome != outcome {
		return errors.New("a different decision is already saved for this request")
	}
	if stored.Message.Expires <= time.Now().Unix() {
		return ErrExpired
	}
	if stored.Delivered {
		return nil
	}
	if err := relay.Send(ctx, stored.Message); err != nil {
		return err
	}
	stored.Delivered = true
	return db.Update(func(tx *bolt.Tx) error {
		raw, err := json.Marshal(stored)
		if err != nil {
			return err
		}
		return tx.Bucket(operatorBucket).Put(id[:], raw)
	})
}

// DecisionProgress reports this operator's local decision and whether the Mailbox
// acknowledged delivery. It does not attest to verification or enforcement by the Door.
func DecisionProgress(db *bolt.DB, id common.Hash) (Outcome, bool, error) {
	stored, err := operatorPrior(db, id)
	return stored.Outcome, stored.Delivered, err
}

func operatorPrior(db *bolt.DB, id common.Hash) (operatorDecision, error) {
	var choice operatorDecision
	err := db.View(func(tx *bolt.Tx) error {
		if b := tx.Bucket(operatorBucket); b != nil {
			if raw := b.Get(id[:]); raw != nil {
				return json.Unmarshal(raw, &choice)
			}
		}
		return nil
	})
	return choice, err
}
