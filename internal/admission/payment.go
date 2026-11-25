package admission

import (
	"context"
	"errors"
	"time"

	"knock/internal/chain"
	"knock/internal/door"
	"knock/internal/identity"

	"github.com/ethereum/go-ethereum/common"
)

type paymentAuthority interface {
	Payment(context.Context, chain.Registry, common.Hash) (chain.Purchase, error)
	Consume(context.Context, chain.Registry, common.Hash, common.Hash, common.Hash, uint64, uint64, *identity.Keys, func(string)) error
}

func (d Diana) Payment(ctx context.Context, registry chain.Registry, commitment common.Hash) (chain.Purchase, error) {
	return d.EVM.Payment(ctx, registry, commitment)
}

func (d Diana) Consume(ctx context.Context, registry chain.Registry, doorID, commitment, session common.Hash, version, deadline uint64,
	keys *identity.Keys, report func(string),
) error {
	return d.EVM.Consume(ctx, registry, doorID, commitment, session, version, deadline, keys, report)
}

func (h Host) fulfillPurchase(ctx context.Context, wrapper delivery, body doorPayload, commitment common.Hash) error {
	payments, ok := h.Authority.(paymentAuthority)
	if !ok || h.SSH == nil || h.publish == nil {
		return errors.New("the Door cannot fulfill paid access")
	}
	a := body.Authorization
	entry, err := h.Journal.get(a.RequestID)
	if err != nil || entry.Outcome != Pending || entry.PaymentReserved {
		return err
	}
	card, err := h.Authority.Door(ctx, a.Door.Account)
	if err != nil {
		return err
	}
	session := SessionReference(a.DoorID, a.RequestID)
	offer, err := card.Details.Policy.PaymentOffer()
	if err != nil {
		return ErrPolicy
	}
	buyer, err := door.ParseAccount(a.Requester.Account)
	if err != nil {
		return ErrInvalid
	}
	currentPass := func(call context.Context) (chain.Purchase, error) {
		pass, err := payments.Payment(call, card.Details.Registry, commitment)
		if err != nil {
			return pass, err
		}
		if pass.Buyer == (common.Address{}) {
			return pass, ErrPending
		}
		if pass.Buyer != common.BytesToAddress(buyer.Bytes) || pass.DoorId != a.DoorID ||
			pass.RedeemBy != uint64(a.Deadline) || !pass.Offer.Matches(offer) {
			return pass, ErrInvalid
		}
		return pass, nil
	}
	pass, err := currentPass(ctx)
	if err != nil {
		return err
	}
	if pass.SessionRef != (common.Hash{}) {
		return ErrInvalid
	}
	checkPolicy := func(call context.Context) error {
		if err := a.valid(card.Details, time.Now().Unix()); err != nil {
			return err
		}
		allowed, err := h.Authority.CanAdmit(call, card.Details, session)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrPolicy
		}
		return nil
	}
	if err := checkPolicy(ctx); err != nil {
		return err
	}
	requester, err := verifyManifest(ctx, h.Authority, card, localBinding(h.Keys), a, wrapper.Manifest)
	if err != nil {
		return err
	}
	recipients := []sessionRecipient{{requester.Binding.Account, requester.Recipient}}
	owner := card.Details.Owner
	if h.lookup != nil && owner != requester.Binding.Account {
		call, cancel := context.WithTimeout(ctx, 4*time.Second)
		if recipient, err := h.lookup(call, owner); err == nil {
			if actor, err := h.Authority.Actor(call, card.Details, owner, recipient); err == nil {
				recipients = append(recipients, sessionRecipient{actor.Binding.Account, actor.Recipient})
			}
		}
		cancel()
	}
	targets, err := h.sealSessionRecipients(session, a, recipients)
	if err != nil {
		return err
	}
	reserved, err := h.Journal.reservePayment(a.RequestID, commitment)
	if err != nil || !reserved {
		return err
	}
	h.progress(session, "Consuming payment "+commitment.Hex())
	report := func(message string) { h.progress(session, message) }
	consumeErr := payments.Consume(ctx, card.Details.Registry, a.DoorID, commitment,
		session, a.Policy, uint64(a.Deadline), h.Keys, report)
	verifyConsumption := func(call context.Context) error {
		pass, err := currentPass(call)
		if err != nil {
			return err
		}
		if pass.SessionRef != session {
			return errors.New("purchase consumption is not finalized for this session")
		}
		return checkPolicy(call)
	}
	if err := verifyConsumption(ctx); err != nil {
		h.progress(session, "Payment confirmed. Access unfulfilled · "+commitment.Hex())
		notice, noticeErr := h.notice(a, body, ProvisionFailed, commitment, commitment, session, nil)
		if noticeErr == nil {
			_, noticeErr = h.Journal.decide(a.RequestID, commitment, commitment, ProvisionFailed, &notice, nil, nil)
		}
		return errors.Join(consumeErr, err, noticeErr)
	}
	recheck := func(call context.Context) error {
		current, err := h.Authority.Door(call, a.Door.Account)
		if err != nil {
			return err
		}
		if err := a.valid(current.Details, time.Now().Unix()); err != nil {
			return err
		}
		if _, err := verifyManifest(call, h.Authority, current, localBinding(h.Keys), a, wrapper.Manifest); err != nil {
			return err
		}
		return verifyConsumption(call)
	}
	return h.provision(ctx, body, commitment, commitment, session, targets, recheck, verifyConsumption)
}
