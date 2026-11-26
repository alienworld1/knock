package admission

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"errors"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	bolt "go.etcd.io/bbolt"

	"knock/internal/chain"
	"knock/internal/door"
	"knock/internal/identity"
	"knock/internal/mailbox"
	"knock/internal/protocol"
)

var historyBucket = []byte("verified-receipt-ciphertext-v1")

func openAuditBundle(card door.Card, keys *identity.Keys, bundle auditBundle) (AuditReceipt, error) {
	var result AuditReceipt
	signed := bundle.Distribution
	dist := signed.Record
	group := auditGroup(card.Details)
	if dist.Group != group || dist.Epoch == 0 || card.VerifySigner(signed.Signing) != nil ||
		protocol.Verify(card.Details.Account, signed.Signing, auditDistributionPurpose, dist, signed.Signature) != nil {
		return result, ErrInvalid
	}
	env, err := qoreseal.ParseEnvelope(dist.Envelope)
	if err != nil || env.Mode != qoreseal.ModeHybrid || len(env.Entries) == 0 || len(env.Entries) > maxAuditMembers {
		return result, ErrInvalid
	}
	key, err := qoreseal.OpenEpochKey(chain.NativeID, auditPurpose(group), dist.Envelope, keys.Recipient)
	defer clear(key.Key)
	if err != nil || key.Epoch != dist.Epoch {
		return result, errors.New("identity cannot open this audit epoch")
	}
	if len(bundle.Blob) == 0 {
		return result, nil
	}
	batch, err := qoreseal.OpenBatch(bundle.Blob, qoreseal.KeysFromList([]qoreseal.EpochKey{key}))
	if err != nil {
		return result, ErrInvalid
	}
	defer clear(batch.Data)
	var receipt signedReceipt
	r := &receipt.Record
	d := card.Details
	if batch.Context != auditContext(group) || protocol.Decode(batch.Data, &receipt) != nil ||
		r.Group != group || r.Epoch != batch.Epoch || r.Index != batch.BatchIndex ||
		r.validate(d.DoorID, d.Registry.Address, d.Account) != nil ||
		protocol.Verify(d.Account, signed.Signing, receiptPurpose, *r, receipt.Signature) != nil {
		return result, ErrInvalid
	}
	return AuditReceipt{sha256.Sum256(bundle.Blob), *r}, nil
}

func recordHistory(db *bolt.DB, receipt AuditReceipt, bundle auditBundle) error {
	return db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(historyBucket)
		if err != nil {
			return err
		}
		key := append(bytes.Clone(receipt.Group[:]), receipt.ID[:]...)
		if b.Get(key) != nil {
			return nil
		}
		return putAudit(b, key, bundle)
	})
}

func ImportAuditReceipt(db *bolt.DB, card door.Card, keys *identity.Keys, raw []byte) error {
	var bundle auditBundle
	if err := protocol.Decode(raw, &bundle); err != nil {
		return err
	}
	receipt, err := openAuditBundle(card, keys, bundle)
	if err != nil {
		return err
	}
	if receipt.ID == (common.Hash{}) {
		return ErrInvalid
	}
	return recordHistory(db, receipt, bundle)
}

// LoadHistory keeps only ciphertext in the auditor's cache and verifies every displayed receipt.
func LoadHistory(ctx context.Context, db *bolt.DB, relay *mailbox.Client, card door.Card, keys *identity.Keys) ([]AuditReceipt, error) {
	var deliveryErr error
	if relay != nil {
		messages, err := relay.Inbox(ctx)
		deliveryErr = err
		for _, message := range messages {
			if message.Route != keys.Account.Bech32 {
				continue
			}
			var bundle auditBundle
			if err := open(message.Body, message.ID, auditDeliveryPurpose, keys.Recipient, 1, &bundle); err != nil {
				continue
			}
			receipt, err := openAuditBundle(card, keys, bundle)
			if err != nil {
				continue
			}
			if receipt.ID != (common.Hash{}) {
				if err := recordHistory(db, receipt, bundle); err != nil {
					return nil, err
				}
			}
			if err := relay.Ack(ctx, message.ID); err != nil {
				deliveryErr = err
			}
		}
	}
	group := auditGroup(card.Details)
	var receipts []AuditReceipt
	err := db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(historyBucket)
		if b == nil {
			return nil
		}
		c := b.Cursor()
		for k, raw := c.Seek(group[:]); bytes.HasPrefix(k, group[:]); k, raw = c.Next() {
			var bundle auditBundle
			if err := protocol.Decode(raw, &bundle); err != nil {
				return err
			}
			receipt, err := openAuditBundle(card, keys, bundle)
			if err != nil || len(k) != 2*sha256.Size || !bytes.Equal(k[sha256.Size:], receipt.ID[:]) {
				return errors.New("couldn't verify a cached receipt")
			}
			receipts = append(receipts, receipt)
		}
		return nil
	})
	slices.SortFunc(receipts, func(a, b AuditReceipt) int { return cmp.Compare(b.Index, a.Index) })
	return receipts, errors.Join(err, deliveryErr)
}

// ExportAuditReceipt returns only the sealed epoch distribution and receipt. The
// host operator may export for an account that belonged to the receipt's epoch.
func ExportAuditReceipt(db *bolt.DB, id common.Hash, account string) ([]byte, error) {
	var bundle auditBundle
	err := db.View(func(tx *bolt.Tx) error {
		archive, epochs := tx.Bucket(auditArchive), tx.Bucket(auditEpochs)
		if archive == nil || epochs == nil {
			return errors.New("audit archive is unavailable")
		}
		var item receiptArchive
		ok, err := readAudit(archive, id[:], &item)
		if err != nil {
			return err
		}
		if !ok || sha256.Sum256(item.Blob) != id {
			return errors.New("receipt is unavailable")
		}
		var epoch epochArchive
		ok, err = readAudit(epochs, auditEpochKey(item.Epoch), &epoch)
		if err != nil {
			return err
		}
		if !ok || !slices.Contains(epoch.Members, account) {
			return errors.New("recipient did not belong to the receipt's audit epoch")
		}
		bundle = auditBundle{epoch.Distribution, item.Blob}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return protocol.Encode(bundle)
}
