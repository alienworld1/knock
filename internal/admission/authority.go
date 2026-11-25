package admission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"knock/internal/chain"
	"knock/internal/door"
	"knock/internal/identity"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
)

type Actor struct {
	Binding   Binding
	Signing   []byte
	Recipient qoreseal.SealRecipient
}

type Authority interface {
	Door(context.Context, string) (door.Card, error)
	Actor(context.Context, door.Details, string, qoreseal.RecipientCard) (Actor, error)
	CanAdmit(context.Context, door.Details, common.Hash) (bool, error)
}

type Diana struct {
	Native   *chain.Native
	EVM      *chain.EVM
	Registry chain.Registry
	Cards    string
	Origin   string
	Expected *door.Config
}

func (d Diana) Door(ctx context.Context, account string) (door.Card, error) {
	if _, err := door.ParseAccount(account); err != nil {
		return door.Card{}, ErrInvalid
	}
	card, err := door.ReadCard(d.Cards, account)
	if err != nil {
		return door.Card{}, err
	}
	if card.Details.Mailbox != d.Origin {
		return door.Card{}, ErrInvalid
	}
	if d.Expected != nil {
		policy, err := d.Expected.Policy.ChainPolicy()
		if err != nil || card.Details.Account != d.Expected.Account || card.Details.DoorID != d.Expected.DoorID ||
			card.Details.Owner != d.Expected.Owner || card.Details.PolicyCommitment != policy.Commitment {
			return door.Card{}, ErrPolicy
		}
	}
	err = card.Verify(ctx, d.Native, d.EVM, d.Registry, account)
	return card, bindingError(err)
}

func (d Diana) Actor(ctx context.Context, details door.Details, account string, card qoreseal.RecipientCard) (Actor, error) {
	address, err := door.ParseAccount(account)
	if err != nil {
		return Actor{}, ErrInvalid
	}
	public, recipient, err := d.Native.RecipientBinding(ctx, card, account)
	if err != nil {
		return Actor{}, bindingError(err)
	}
	state, block, err := d.EVM.Door(ctx, details.Registry, details.DoorID)
	if err != nil {
		return Actor{}, bindingError(err)
	}
	if state.Version != details.Policy.Version || state.Policy.Commitment != details.PolicyCommitment || !state.Policy.Enabled {
		return Actor{}, ErrPolicy
	}
	if err := d.EVM.Binding(ctx, address, public, block); err != nil {
		return Actor{}, bindingError(err)
	}
	return Actor{binding(account, public, recipient), public, recipient}, nil
}

func (d Diana) CanAdmit(ctx context.Context, details door.Details, session common.Hash) (bool, error) {
	return d.EVM.CanAdmit(ctx, details.Registry, details.DoorID, session, details.Policy.Version, details.PolicyCommitment)
}

func bindingError(err error) error {
	if errors.Is(err, chain.ErrIdentityBinding) {
		return fmt.Errorf("%w: %w", ErrInvalid, err)
	}
	return err
}

func RecipientCard(keys *identity.Keys) (qoreseal.RecipientCard, error) {
	return qoreseal.SignRecipientCard(qoreseal.SignRecipientCardArgs{
		ChainID: chain.NativeID, Address: keys.Account.Bech32, Keys: keys.Recipient,
		ClassicalKey: keys.Classical, PqKey: keys.Signing,
	})
}

func (a Binding) Matches(keys *identity.Keys) bool {
	return a == localBinding(keys)
}

func verifyManifest(ctx context.Context, authority Authority, card door.Card, currentDoor Binding, a authorization, signed signedManifest) (Actor, error) {
	m := signed.Record
	d := card.Details
	digest, err := protocol.Digest(a)
	if err != nil || m.Authorization != digest || m.RequestID != a.RequestID ||
		m.Door != a.Door || m.Door != currentDoor || m.DoorID != a.DoorID ||
		m.Requester != a.Requester || m.Deadline != a.Deadline || m.Mode != d.Mode ||
		m.DoorEnvelope == (common.Hash{}) || (d.Mode == door.Metered) != (m.ReviewEnvelope == (common.Hash{})) ||
		len(m.Approvers) != len(d.Policy.Approvers) {
		return Actor{}, ErrInvalid
	}
	for i, approver := range m.Approvers {
		if approver.Account != d.Policy.Approvers[i] || approver.Account == a.Requester.Account || approver.Account == d.Account ||
			approver.Signing == (common.Hash{}) || approver.KEM == (common.Hash{}) || approver.X25519 == (common.Hash{}) {
			return Actor{}, ErrInvalid
		}
	}
	requester, err := authority.Actor(ctx, d, a.Requester.Account, m.RequesterCard)
	if err != nil {
		return Actor{}, err
	}
	if requester.Binding != a.Requester ||
		protocol.Verify(a.Requester.Account, requester.Signing, manifestPurpose, m, signed.Signature) != nil {
		return Actor{}, ErrInvalid
	}
	return requester, nil
}

func approverBinding(m manifest, account string) (Binding, bool) {
	for _, actor := range m.Approvers {
		if actor.Account == account {
			return actor, true
		}
	}
	return Binding{}, false
}

func CardBinding(card door.Card) (Binding, error) {
	d := card.Details
	public, err := hex.DecodeString(d.Recipient.X25519PublicKey)
	if err != nil || qoreseal.ValidateX25519PublicKey(public) != nil {
		return Binding{}, ErrInvalid
	}
	return Binding{d.Account, d.SigningKey, d.KEMKey, sha256.Sum256(public)}, nil
}
