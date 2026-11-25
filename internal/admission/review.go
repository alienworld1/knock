package admission

import (
	"context"
	"slices"
	"time"

	"knock/internal/identity"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
)

type Review struct {
	intent approvalPayload
	signed signedManifest
}

type ReviewSummary struct {
	ID        common.Hash `json:"id"`
	Door      string      `json:"door"`
	Requester string      `json:"requester"`
	Service   string      `json:"service"`
	Role      string      `json:"role"`
	Seconds   uint64      `json:"durationSeconds"`
	Deadline  time.Time   `json:"deadline"`
}

func (r Review) Summary() ReviewSummary {
	a := r.intent.Authorization
	return ReviewSummary{a.RequestID, a.Door.Account, a.Requester.Account, a.Service, a.Role, a.Seconds, time.Unix(a.Deadline, 0).UTC()}
}

func (r Review) Reason() string { return r.intent.Reason }

func OpenReview(ctx context.Context, authority Authority, keys *identity.Keys, message mailbox.Message, target common.Hash) (Review, error) {
	var wrapper delivery
	if message.Route != keys.Account.Bech32 ||
		open(message.Body, message.ID, reviewDelivery, keys.Recipient, 8, &wrapper) != nil {
		return Review{}, ErrInvalid
	}
	m := wrapper.Manifest.Record
	if target != (common.Hash{}) && m.RequestID != target {
		return Review{}, ErrInvalid
	}
	var intent approvalPayload
	if message.ID != recordID(reviewDelivery, m.DoorID, m.RequestID, "") || message.Expires != m.Deadline ||
		!checkedDigest(wrapper.Inner, m.ReviewEnvelope) ||
		open(wrapper.Inner, message.ID, reviewInner, keys.Recipient, 8, &intent) != nil ||
		intent.DoorEnvelope != m.DoorEnvelope || intent.ReviewSalt == (common.Hash{}) || !ValidReason(intent.Reason) {
		return Review{}, ErrInvalid
	}
	card, err := authority.Door(ctx, m.Door.Account)
	if err != nil {
		return Review{}, err
	}
	d := card.Details
	a := intent.Authorization
	if err := a.valid(d, time.Now().Unix()); err != nil {
		return Review{}, err
	}
	expected, eligible := approverBinding(m, keys.Account.Bech32)
	if !eligible || !slices.Contains(d.Policy.Approvers, keys.Account.Bech32) {
		return Review{}, ErrInvalid
	}
	ownCard, err := RecipientCard(keys)
	if err != nil {
		return Review{}, err
	}
	approver, err := authority.Actor(ctx, d, keys.Account.Bech32, ownCard)
	if err != nil {
		return Review{}, err
	}
	if expected != approver.Binding || !approver.Binding.Matches(keys) {
		return Review{}, ErrInvalid
	}
	doorBinding, err := CardBinding(card)
	if err != nil {
		return Review{}, err
	}
	if err := verifyManifest(ctx, authority, card, doorBinding, a, wrapper.Manifest); err != nil {
		return Review{}, err
	}
	return Review{intent, wrapper.Manifest}, nil
}

func (r Review) Decision(ctx context.Context, authority Authority, keys *identity.Keys, outcome Outcome) (mailbox.Message, error) {
	if outcome != Authorized && outcome != Denied {
		return mailbox.Message{}, ErrInvalid
	}
	a := r.intent.Authorization
	card, err := authority.Door(ctx, a.Door.Account)
	if err != nil {
		return mailbox.Message{}, err
	}
	d := card.Details
	if err := a.valid(d, time.Now().Unix()); err != nil {
		return mailbox.Message{}, err
	}
	if !slices.Contains(d.Policy.Approvers, keys.Account.Bech32) {
		return mailbox.Message{}, ErrPolicy
	}
	actor, err := authority.Actor(ctx, d, d.Account, d.Recipient)
	if err != nil {
		return mailbox.Message{}, err
	}
	if err := verifyManifest(ctx, authority, card, actor.Binding, a, r.signed); err != nil {
		return mailbox.Message{}, err
	}
	m, err := protocol.Digest(r.signed)
	if err != nil {
		return mailbox.Message{}, err
	}
	reviewed, err := protocol.Digest(r.intent)
	if err != nil {
		return mailbox.Message{}, err
	}
	publicCard, err := RecipientCard(keys)
	if err != nil {
		return mailbox.Message{}, err
	}
	signer, err := authority.Actor(ctx, d, keys.Account.Bech32, publicCard)
	if err != nil {
		return mailbox.Message{}, err
	}
	expected, ok := approverBinding(r.signed.Record, keys.Account.Bech32)
	if !ok || signer.Binding != expected || !signer.Binding.Matches(keys) {
		return mailbox.Message{}, ErrInvalid
	}
	now := time.Now().Unix()
	if now >= a.Deadline {
		return mailbox.Message{}, ErrExpired
	}
	decision := decision{a, m, r.intent.DoorEnvelope, reviewed, signer.Binding, publicCard, outcome, now, a.Deadline}
	sig, err := protocol.Sign(keys, decisionPurpose, decision)
	if err != nil {
		return mailbox.Message{}, err
	}
	id := decisionID(decision)
	sealed, err := seal(signedDecision{decision, sig}, id, decisionPurpose, actor.Recipient)
	return mailbox.Message{Route: d.Account, ID: id, Expires: a.Deadline, Body: sealed}, err
}

func decisionID(d decision) common.Hash {
	a := d.Authorization
	return recordID(decisionPurpose, a.DoorID, a.RequestID, d.Approver.Account+"/"+string(d.Outcome))
}

func localBinding(keys *identity.Keys) Binding {
	return binding(keys.Account.Bech32, keys.Signing.PublicKey, qoreseal.RecipientOf(keys.Recipient))
}
