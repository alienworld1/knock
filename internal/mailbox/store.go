package mailbox

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	bolt "go.etcd.io/bbolt"
)

var (
	queueBucket = []byte("messages-v1")
	cardBucket  = []byte("cards-v1")
)

const maxRecords = 512

type stored struct {
	Message Message
	Sender  string
	Digest  common.Hash
}

func routePrefix(account string) []byte { return []byte(account + "/") }

func messageKey(account string, id common.Hash) []byte {
	return append(routePrefix(account), id[:]...)
}

func (s *Server) prune(now int64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(queueBucket).Cursor()
		var expired [][]byte
		for key, raw := c.First(); key != nil; key, raw = c.Next() {
			var item stored
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			if item.Message.Expires <= now {
				expired = append(expired, bytes.Clone(key))
			}
		}
		for _, key := range expired {
			if err := tx.Bucket(queueBucket).Delete(key); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Server) send(account string, message Message, now int64) (int, error) {
	code := http.StatusNoContent
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(queueBucket)
		key := messageKey(message.Route, message.ID)
		digest := sha256.Sum256(message.Body)
		if raw := b.Get(key); raw != nil {
			var old stored
			if err := json.Unmarshal(raw, &old); err != nil {
				return err
			}
			if old.Digest != digest || old.Sender != account || old.Message.Expires != message.Expires {
				code = http.StatusConflict
			}
			return nil
		}
		if b.Stats().KeyN >= maxRecords {
			code = http.StatusTooManyRequests
			return nil
		}
		prefix := routePrefix(message.Route)
		c := b.Cursor()
		active := 0
		for k, raw := c.Seek(prefix); bytes.HasPrefix(k, prefix); k, raw = c.Next() {
			var old stored
			if err := json.Unmarshal(raw, &old); err != nil {
				return err
			}
			if old.Message.Expires > now && len(old.Message.Body) != 0 {
				active++
			}
		}
		if active >= MaxInbox {
			code = http.StatusTooManyRequests
			return nil
		}
		raw, err := json.Marshal(stored{message, account, digest})
		if err != nil {
			return err
		}
		return b.Put(key, raw)
	})
	return code, err
}

func (s *Server) inbox(account string, after common.Hash, now int64) (page, error) {
	result := page{Messages: []Message{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		prefix := routePrefix(account)
		c := tx.Bucket(queueBucket).Cursor()
		for k, raw := c.Seek(messageKey(account, after)); bytes.HasPrefix(k, prefix); k, raw = c.Next() {
			if bytes.Compare(k[len(prefix):], after[:]) <= 0 {
				continue
			}
			var item stored
			if err := json.Unmarshal(raw, &item); err != nil {
				return err
			}
			if item.Message.Expires <= now || len(item.Message.Body) == 0 {
				continue
			}
			if len(result.Messages) == PageSize {
				next := result.Messages[len(result.Messages)-1].ID
				result.Next = &next
				break
			}
			result.Messages = append(result.Messages, item.Message)
		}
		return nil
	})
	return result, err
}

func (s *Server) ack(account string, id common.Hash) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(queueBucket)
		key := messageKey(account, id)
		raw := b.Get(key)
		if raw == nil {
			return nil
		}
		var item stored
		if err := json.Unmarshal(raw, &item); err != nil {
			return err
		}
		if len(item.Message.Body) == 0 {
			return nil
		}
		item.Message.Body = nil
		replacement, err := json.Marshal(item)
		if err != nil {
			return err
		}
		return b.Put(key, replacement)
	})
}

func (s *Server) saveCard(account string, card qoreseal.RecipientCard) (int, error) {
	code := http.StatusNoContent
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(cardBucket)
		key := []byte(account)
		raw, err := json.Marshal(card)
		if err != nil {
			return err
		}
		if previous := b.Get(key); previous != nil {
			if bytes.Equal(previous, raw) {
				return nil
			}
			var prior qoreseal.RecipientCard
			if err := json.Unmarshal(previous, &prior); err != nil {
				return err
			}
			issued, _ := time.Parse(time.RFC3339, card.IssuedAt)
			previousIssue, _ := time.Parse(time.RFC3339, prior.IssuedAt)
			if !issued.After(previousIssue) {
				code = http.StatusConflict
				return nil
			}
		} else if b.Stats().KeyN >= maxRecords {
			code = http.StatusTooManyRequests
			return nil
		}
		return b.Put(key, raw)
	})
	return code, err
}
