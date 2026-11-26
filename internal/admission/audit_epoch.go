package admission

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
	bolt "go.etcd.io/bbolt"

	"knock/internal/chain"
	"knock/internal/door"
	"knock/internal/identity"
	"knock/internal/mailbox"
	"knock/internal/protocol"
)

const (
	auditRotatePurpose       = "knock-audit-rotate-v1"
	auditDistributionPurpose = "knock-audit-distribution-v1"
	auditDeliveryPurpose     = "knock-audit-delivery-v1"
	maxAuditMembers          = 16
	maxAuditState            = 64 << 10
)

var (
	auditEpochs          = []byte("audit-epochs-v1")
	auditArchive         = []byte("audit-archive-v1")
	auditOutbox          = []byte("audit-outbox-v1")
	currentEpoch         = []byte("current")
	pendingEpoch         = []byte("pending")
	errAuditUnconfigured = errors.New("audit membership has not been configured")
	errAuditNoMembers    = errors.New("the audit epoch has no members")
)

// Audit serializes epoch changes and receipt issuance for one Door.
type Audit struct {
	mu     sync.Mutex
	db     *bolt.DB
	path   string
	group  common.Hash
	wrap   *age.ScryptRecipient
	unwrap *age.ScryptIdentity
	loaded epochMarker
	state  epochState
}

type epochState struct {
	Group   common.Hash
	Key     qoreseal.EpochKey
	Members []qoreseal.Member
}

type epochMarker struct {
	Epoch uint64
	Hash  common.Hash
}

type distribution struct {
	Group    common.Hash
	Epoch    uint64
	Envelope []byte
}

type signedDistribution struct {
	Record    distribution
	Signing   []byte
	Signature qoresign.MessageSignature
}

type rotation struct {
	Group   common.Hash
	Policy  common.Hash
	From    uint64
	Members []string
	Expires int64
}

type signedRotation struct {
	Record    rotation
	Signature qoresign.MessageSignature
}

func auditGroup(d door.Details) common.Hash {
	return recordID("knock-audit-group-v1", d.DoorID, common.BytesToHash(d.Registry.Address[:]), d.Account)
}

func auditPurpose(group common.Hash) string { return "knock-audit-epoch-v1/" + group.Hex() }

func auditContext(group common.Hash) string { return "knock-receipts-v1/" + group.Hex() }

func NewAudit(j *Journal, path string, details door.Details, passphrase []byte) (*Audit, error) {
	wrap, err := age.NewScryptRecipient(string(passphrase))
	if err != nil {
		return nil, err
	}
	unwrap, err := age.NewScryptIdentity(string(passphrase))
	if err != nil {
		return nil, err
	}
	unwrap.SetMaxWorkFactor(18)
	err = j.db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{auditEpochs, auditArchive, auditOutbox} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	})
	return &Audit{db: j.db, path: path, group: auditGroup(details), wrap: wrap, unwrap: unwrap}, err
}

func (a *Audit) Clear() { clear(a.state.Key.Key) }

func auditMembers(accounts []string) bool {
	if len(accounts) > maxAuditMembers || !slices.IsSorted(accounts) {
		return false
	}
	for i, account := range accounts {
		if _, err := door.ParseAccount(account); err != nil || (i != 0 && accounts[i-1] == account) {
			return false
		}
	}
	return true
}

// SendAuditRotation queues an owner-signed full membership replacement for the expected epoch.
func SendAuditRotation(ctx context.Context, relay *mailbox.Client, card door.Card, owner *identity.Keys, recipient qoreseal.SealRecipient, from uint64, members []string) error {
	members = slices.Clone(members)
	slices.Sort(members)
	if card.Details.Owner != owner.Account.Bech32 || !auditMembers(members) || from == ^uint64(0) {
		return errors.New("use the Door owner identity, a valid epoch and up to 16 distinct auditor accounts")
	}
	r := rotation{auditGroup(card.Details), card.Details.PolicyCommitment, from, members, time.Now().Add(5 * time.Minute).Unix()}
	sig, err := protocol.Sign(owner, auditRotatePurpose, r)
	if err != nil {
		return err
	}
	id, err := protocol.Digest(r)
	if err != nil {
		return err
	}
	body, err := seal(signedRotation{r, sig}, id, auditRotatePurpose, recipient)
	if err != nil {
		return err
	}
	return relay.Send(ctx, mailbox.Message{Route: card.Details.Account, ID: id, Expires: r.Expires, Body: body})
}

func (h Host) rotateAudit(ctx context.Context, message mailbox.Message, signed signedRotation) error {
	if h.Audit == nil || h.lookup == nil {
		return ErrInvalid
	}
	r := signed.Record
	id, err := protocol.Digest(r)
	if err != nil || id != message.ID || r.Expires != message.Expires || !auditMembers(r.Members) || r.Group != h.Audit.group {
		return ErrInvalid
	}
	card, err := h.Authority.Door(ctx, h.Keys.Account.Bech32)
	if err != nil {
		return err
	}
	if auditGroup(card.Details) != r.Group || card.Details.PolicyCommitment != r.Policy || !card.Details.Policy.Enabled {
		return ErrPolicy
	}
	// Door verification checks the owner against finalized policy. Verify the
	// signed request against that account's current registered signing key.
	public, err := h.Authority.SigningKey(ctx, card.Details.Owner)
	if err != nil {
		return err
	}
	if protocol.Verify(card.Details.Owner, public, auditRotatePurpose, r, signed.Signature) != nil {
		return ErrInvalid
	}
	members := make([]qoreseal.Member, 0, len(r.Members))
	for _, account := range r.Members {
		recipient, err := h.lookup(ctx, account)
		if err != nil {
			return err
		}
		actor, err := h.Authority.Actor(ctx, card.Details, account, recipient)
		if err != nil {
			return err
		}
		if actor.Binding.Account != account || !h.validX25519(actor.Recipient.X25519PublicKey) {
			return ErrInvalid
		}
		members = append(members, qoreseal.Member{ID: account, Recipient: actor.Recipient})
	}
	if time.Now().Unix() >= r.Expires {
		return ErrExpired
	}
	// Resolution may take time. Recheck the current policy before applying it.
	current, err := h.Authority.Door(ctx, h.Keys.Account.Bech32)
	if err != nil {
		return err
	}
	if auditGroup(current.Details) != r.Group || current.Details.PolicyCommitment != r.Policy || current.Details.Owner != card.Details.Owner {
		return ErrPolicy
	}
	if err := h.Audit.rotate(h.Keys, r.From, members); err != nil {
		if errors.Is(err, ErrPolicy) && h.Progress != nil {
			h.Progress(fmt.Sprintf("Audit rotation skipped. Epoch %d is no longer current.", r.From))
		}
		return err
	}
	if h.Progress != nil {
		h.Progress(fmt.Sprintf("Audit epoch %d ready", r.From+1))
	}
	return nil
}

func (a *Audit) rotate(keys *identity.Keys, from uint64, members []qoreseal.Member) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	state, err := a.recover(keys)
	if err != nil && !errors.Is(err, errAuditUnconfigured) {
		return err
	}
	if from != state.Key.Epoch || from == ^uint64(0) {
		return ErrPolicy
	}
	opts := qoreseal.EpochKeyManagerOptions{ChainID: chain.NativeID, Purpose: auditPurpose(a.group), Mode: qoreseal.ModeHybrid}
	if from != 0 {
		opts.History = []qoreseal.EpochKey{state.Key}
	}
	manager, err := qoreseal.NewEpochKeyManager(opts)
	if err != nil {
		return err
	}
	if from != 0 {
		if _, err := manager.Rotate(); err != nil {
			return err
		}
	}
	key := manager.CurrentKey()
	defer clear(key.Key)
	if err := a.stage(epochState{a.group, key, members}); err != nil {
		return err
	}
	_, err = a.recover(keys)
	return err
}

func putAudit(b *bolt.Bucket, k []byte, value any) error {
	raw, err := protocol.Encode(value)
	if err != nil {
		return err
	}
	return b.Put(k, raw)
}

func readAudit(b *bolt.Bucket, k []byte, value any) (bool, error) {
	raw := b.Get(k)
	if raw == nil {
		return false, nil
	}
	return true, protocol.Decode(raw, value)
}

func syncAuditDir(path string) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Stage and sync a wrapped candidate. Its presence blocks issuance until recovery
// installs the matching DB marker and commits the rotation.
func (a *Audit) stage(state epochState) error {
	raw, err := protocol.Encode(state)
	if err != nil {
		return err
	}
	defer clear(raw)
	var ciphertext bytes.Buffer
	w, err := age.Encrypt(&ciphertext, a.wrap)
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(a.path), ".audit-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	defer file.Close()
	if _, err := file.Write(ciphertext.Bytes()); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), a.path+".pending"); err != nil {
		return err
	}
	return syncAuditDir(a.path)
}

func readAuditFile(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > maxAuditState {
		return nil, errors.New("invalid wrapped audit state file")
	}
	return os.ReadFile(path)
}

// recover runs under the audit mutex. A staged file is already a pending
// rotation, even if the process stopped before writing the matching DB marker.
func (a *Audit) recover(keys *identity.Keys) (epochState, error) {
	var current, pending epochMarker
	err := a.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket(auditEpochs)
		_, activeErr := readAudit(b, currentEpoch, &current)
		_, pendingErr := readAudit(b, pendingEpoch, &pending)
		return errors.Join(activeErr, pendingErr)
	})
	if err != nil {
		return epochState{}, err
	}

	staged, stagedErr := readAuditFile(a.path + ".pending")
	if stagedErr != nil && !errors.Is(stagedErr, os.ErrNotExist) {
		return epochState{}, stagedErr
	}
	if pending.Epoch == 0 && stagedErr == nil {
		pending = epochMarker{current.Epoch + 1, sha256.Sum256(staged)}
		if pending.Epoch == 0 {
			return epochState{}, errors.New("audit epoch exhausted")
		}
		if err := a.loadEpoch(pending, staged); err != nil {
			return epochState{}, err
		}
		if err := syncAuditDir(a.path); err != nil {
			return epochState{}, err
		}
		if err := a.db.Update(func(tx *bolt.Tx) error {
			return putAudit(tx.Bucket(auditEpochs), pendingEpoch, pending)
		}); err != nil {
			return epochState{}, err
		}
	}

	active, activeErr := readAuditFile(a.path)
	if pending.Epoch == 0 {
		if current.Epoch == 0 && errors.Is(activeErr, os.ErrNotExist) {
			return epochState{}, errAuditUnconfigured
		}
		if activeErr != nil {
			return epochState{}, activeErr
		}
		if err := a.loadEpoch(current, active); err != nil {
			return epochState{}, err
		}
		return a.state, nil
	}

	if pending.Epoch != current.Epoch+1 {
		return epochState{}, errors.New("audit rotation marker does not follow the current epoch")
	}
	if stagedErr == nil {
		if err := a.loadEpoch(pending, staged); err != nil {
			return epochState{}, err
		}
		if err := os.Rename(a.path+".pending", a.path); err != nil {
			return epochState{}, err
		}
	} else {
		if activeErr != nil {
			return epochState{}, errors.New("couldn't recover the pending audit rotation")
		}
		if err := a.loadEpoch(pending, active); err != nil {
			return epochState{}, err
		}
	}
	if err := syncAuditDir(a.path); err != nil {
		return epochState{}, err
	}
	if err := a.commitRotation(keys, pending); err != nil {
		return epochState{}, err
	}
	return a.state, nil
}

func (a *Audit) loadEpoch(marker epochMarker, ciphertext []byte) error {
	if marker.Epoch == 0 || sha256.Sum256(ciphertext) != marker.Hash {
		return errors.New("wrapped audit state does not match the expected epoch")
	}
	if a.loaded == marker {
		return nil
	}
	r, err := age.Decrypt(bytes.NewReader(ciphertext), a.unwrap)
	if err != nil {
		return fmt.Errorf("unlock wrapped audit state: %w", err)
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxAuditState+1))
	defer clear(raw)
	var state epochState
	if err != nil || len(raw) > maxAuditState || protocol.Decode(raw, &state) != nil ||
		state.Group != a.group || state.Key.Epoch != marker.Epoch || len(state.Key.Key) != 32 ||
		!auditMembers(auditMemberIDs(state.Members)) {
		clear(state.Key.Key)
		return errors.New("invalid wrapped audit epoch")
	}
	clear(a.state.Key.Key)
	a.state, a.loaded = state, marker
	return nil
}

func (a *Audit) commitRotation(keys *identity.Keys, marker epochMarker) error {
	state := a.state
	var archive epochArchive
	var outbox []mailbox.Message
	if len(state.Members) != 0 {
		manager, err := qoreseal.NewEpochKeyManager(qoreseal.EpochKeyManagerOptions{
			ChainID: chain.NativeID, Purpose: auditPurpose(a.group), Mode: qoreseal.ModeHybrid,
			Members: state.Members, History: []qoreseal.EpochKey{state.Key},
		})
		if err != nil {
			return err
		}
		envelope, err := manager.Distribution()
		if err != nil {
			return err
		}
		dist := distribution{a.group, marker.Epoch, envelope}
		sig, err := protocol.Sign(keys, auditDistributionPurpose, dist)
		if err != nil {
			return err
		}
		signed := signedDistribution{dist, keys.Signing.PublicKey, sig}
		archive = epochArchive{signed, auditMemberIDs(state.Members)}
		outbox, err = auditDeliveries(auditBundle{Distribution: signed}, state.Members)
		if err != nil {
			return err
		}
	}
	return a.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(auditEpochs)
		if err := putAudit(b, currentEpoch, marker); err != nil {
			return err
		}
		if len(state.Members) != 0 {
			if err := putAudit(b, auditEpochKey(marker.Epoch), archive); err != nil {
				return err
			}
		}
		if err := queueAudit(tx, outbox); err != nil {
			return err
		}
		return b.Delete(pendingEpoch)
	})
}

func auditMemberIDs(members []qoreseal.Member) []string {
	ids := make([]string, 0, len(members))
	for _, member := range members {
		ids = append(ids, member.ID)
	}
	return ids
}
