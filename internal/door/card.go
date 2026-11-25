package door

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"knock/internal/chain"
	"knock/internal/identity"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
)

type Policy struct {
	Version            uint64   `json:"version"`
	Enabled            bool     `json:"enabled"`
	MaxDurationSeconds uint64   `json:"maxDurationSeconds"`
	ApproversCanRevoke bool     `json:"approversCanRevoke"`
	Approvers          []string `json:"approvers"`
	Roles              []string `json:"roles"`
}

type Details struct {
	Version          uint64                 `json:"version"`
	NativeChain      string                 `json:"nativeChain"`
	EVMChain         uint64                 `json:"evmChain"`
	Registry         chain.Registry         `json:"registry"`
	DoorID           common.Hash            `json:"doorId"`
	Account          string                 `json:"account"`
	Owner            string                 `json:"owner"`
	SigningKey       [32]byte               `json:"signingKey"`
	KEMKey           [32]byte               `json:"kemKey"`
	Recipient        qoreseal.RecipientCard `json:"recipient"`
	Policy           Policy                 `json:"policy"`
	PolicyCommitment common.Hash            `json:"policyCommitment"`
	Mode             string                 `json:"mode"`
	Inbox            common.Hash            `json:"inbox"`
	Mailbox          string                 `json:"mailbox,omitempty"`
	Issued           int64                  `json:"issued"`
	Expires          int64                  `json:"expires"`
}

type Card struct {
	Details   Details                   `json:"details"`
	Signature qoresign.MessageSignature `json:"signature"`
}

const (
	MaxCardSize = 24 << 10
	lifetime    = 24 * time.Hour
	cardPurpose = "knock-door-card-v1"
)

var encoding, _ = cbor.CoreDetEncOptions().EncMode()
var decoding, _ = (cbor.DecOptions{
	DupMapKey:         cbor.DupMapKeyEnforcedAPF,
	IndefLength:       cbor.IndefLengthForbidden,
	TagsMd:            cbor.TagsForbidden,
	MaxNestedLevels:   8,
	MaxArrayElements:  32,
	MaxMapPairs:       32,
	ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
}).DecMode()

func ParseAccount(account string) (qoresign.AccountAddress, error) {
	parsed, err := qoresign.ParseAddress(account)
	if err != nil || parsed.Bech32 != account {
		return qoresign.AccountAddress{}, errors.New("expected a canonical qor1 account address")
	}
	return parsed, nil
}

func (p Policy) ChainPolicy() (chain.Policy, error) {
	if p.Version == 0 || p.MaxDurationSeconds == 0 || p.MaxDurationSeconds > uint64((1<<63-1)/time.Second) ||
		len(p.Approvers) == 0 || len(p.Approvers) > 8 || len(p.Roles) == 0 || len(p.Roles) > 2 {
		return chain.Policy{}, errors.New("policy needs a version, a positive duration, roles, and one to eight approvers")
	}
	if !slices.IsSorted(p.Roles) || (len(p.Roles) == 2 && p.Roles[0] == p.Roles[1]) {
		return chain.Policy{}, errors.New("policy roles must be unique and sorted")
	}
	for _, role := range p.Roles {
		if role != "logs" && role != "maintenance" {
			return chain.Policy{}, errors.New("policy contains an unsupported role")
		}
	}
	approvers := make([]common.Address, 0, len(p.Approvers))
	for _, account := range p.Approvers {
		parsed, err := ParseAccount(account)
		if err != nil {
			return chain.Policy{}, err
		}
		address := common.BytesToAddress(parsed.Bytes)
		if address == (common.Address{}) || (len(approvers) > 0 && bytes.Compare(approvers[len(approvers)-1][:], address[:]) >= 0) {
			return chain.Policy{}, errors.New("approvers must be unique and sorted by their EVM address bytes")
		}
		approvers = append(approvers, address)
	}
	data, err := encoding.Marshal(p)
	if err != nil {
		return chain.Policy{}, err
	}
	return chain.Policy{
		Commitment: sha256.Sum256(data), Enabled: p.Enabled, ApproversCanRevoke: p.ApproversCanRevoke, Approvers: approvers,
	}, nil
}

func NewCard(config Config, owner string, keys *identity.Keys, recipient qoreseal.RecipientCard, now time.Time) (Card, error) {
	policy, err := config.Policy.ChainPolicy()
	if err != nil {
		return Card{}, err
	}
	details := Details{
		Version: 1, NativeChain: chain.NativeID, EVMChain: chain.EVMID, Registry: config.Registry, DoorID: config.DoorID,
		Account: keys.Account.Bech32, Owner: owner, SigningKey: sha256.Sum256(keys.Signing.PublicKey),
		KEMKey: sha256.Sum256(keys.Recipient.MlkemPublicKey), Recipient: recipient,
		Policy: config.Policy, PolicyCommitment: policy.Commitment, Mode: "approval", Inbox: config.DoorID, Mailbox: config.Mailbox,
		Issued: now.Unix(), Expires: now.Add(lifetime).Unix(),
	}
	data, err := details.signBytes()
	if err != nil {
		return Card{}, err
	}
	signature, err := qoresign.SignMessage(qoresign.SignMessageArgs{
		ChainID: chain.NativeID, Signer: details.Account, Data: data, ClassicalKey: keys.Classical,
		PqKey: &keys.Signing, Hedged: true,
	})
	return Card{Details: details, Signature: signature}, err
}

func (d Details) signBytes() ([]byte, error) {
	return encoding.Marshal(struct {
		Purpose string
		Details Details
	}{cardPurpose, d})
}

func (c Card) Encode() ([]byte, error) {
	return encoding.Marshal(c)
}

func Decode(data []byte) (Card, error) {
	var card Card
	if len(data) > MaxCardSize {
		return card, errors.New("Door Card is too large")
	}
	if err := decoding.Unmarshal(data, &card); err != nil {
		return Card{}, fmt.Errorf("invalid Door Card: %w", err)
	}
	canonical, err := card.Encode()
	if err != nil || !bytes.Equal(data, canonical) {
		return Card{}, errors.New("Door Card has a noncanonical encoding")
	}
	return card, nil
}

func (c Card) Verify(ctx context.Context, n *chain.Native, e *chain.EVM, registry chain.Registry, account string) error {
	d := c.Details
	now := time.Now().Unix()
	if d.Version != 1 || d.NativeChain != chain.NativeID || d.EVMChain != chain.EVMID || d.Registry != registry ||
		d.DoorID == (common.Hash{}) || d.Inbox != d.DoorID || d.Mode != "approval" || d.Account != account {
		return errors.New("Door Card does not match the expected identity, network or registry")
	}
	if d.Mailbox != "" {
		if _, err := protocol.Origin(d.Mailbox); err != nil {
			return err
		}
	}
	if d.Issued < now-int64(lifetime/time.Second) || d.Issued > now+5 || d.Expires <= now ||
		d.Expires != d.Issued+int64(lifetime/time.Second) {
		return errors.New("Door Card has expired or has an invalid issue time")
	}
	doorAccount, err := ParseAccount(d.Account)
	if err != nil {
		return err
	}
	ownerAccount, err := ParseAccount(d.Owner)
	if err != nil {
		return err
	}
	policy, err := d.Policy.ChainPolicy()
	if err != nil {
		return err
	}
	if policy.Commitment != d.PolicyCommitment {
		return errors.New("Door Card policy commitment is invalid")
	}
	signing, err := n.SigningKey(ctx, d.Account)
	if err != nil {
		return err
	}
	if err := c.VerifySigner(signing); err != nil {
		return err
	}
	recipient, err := n.Recipient(ctx, d.Recipient, d.Account)
	if err != nil {
		return err
	}
	if sha256.Sum256(recipient.MlkemPublicKey) != d.KEMKey {
		return errors.New("Door Card recipient key does not match the current identity")
	}
	onchain, block, err := e.Door(ctx, registry, d.DoorID)
	if err != nil {
		return err
	}
	if onchain.Owner != common.BytesToAddress(ownerAccount.Bytes) || onchain.Account != common.BytesToAddress(doorAccount.Bytes) ||
		onchain.Version != d.Policy.Version || !matchesPolicy(onchain.Policy, policy) {
		return errors.New("Door Card policy or owner does not match the finalized registry")
	}
	if err := e.Binding(ctx, doorAccount, signing, block); err != nil {
		return err
	}
	ownerKey, err := n.SigningKey(ctx, d.Owner)
	if err != nil {
		return err
	}
	return e.Binding(ctx, ownerAccount, ownerKey, block)
}

// VerifySigner checks the signed Card against an already trusted signing key.
func (c Card) VerifySigner(signing []byte) error {
	d := c.Details
	if sha256.Sum256(signing) != d.SigningKey || c.Signature.Classical.KeyType != qoresign.EthSecp256k1 {
		return errors.New("Door Card signing key does not match the current identity")
	}
	data, err := d.signBytes()
	if err != nil {
		return err
	}
	if err := qoresign.VerifyMessage(qoresign.VerifyMessageOptions{
		ChainID: chain.NativeID, Signer: d.Account, Data: data, Signature: c.Signature, PqPublicKey: signing,
	}); err != nil {
		return errors.New("Door Card signature could not be verified")
	}
	return nil
}

func matchesPolicy(left, right chain.Policy) bool {
	return left.Commitment == right.Commitment && left.Enabled == right.Enabled &&
		left.ApproversCanRevoke == right.ApproversCanRevoke && slices.Equal(left.Approvers, right.Approvers)
}

func IsAlias(name string) bool {
	if len(name) == 0 || len(name) > 40 || strings.HasPrefix(name, "qor1") || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for _, char := range name {
		if char != '-' && (char < 'a' || char > 'z') && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}
