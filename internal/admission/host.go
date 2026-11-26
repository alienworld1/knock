package admission

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"

	"knock/internal/identity"
	"knock/internal/lease"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
)

type Host struct {
	Authority Authority
	Keys      *identity.Keys
	Journal   *Journal
	SSH       *lease.Host
	Audit     *Audit
	Progress  func(string)
	publish   func(context.Context, mailbox.Message) error
	lookup    func(context.Context, string) (qoreseal.RecipientCard, error)
}

func (h Host) Receive(ctx context.Context, message mailbox.Message) error {
	if message.Route != h.Keys.Account.Bech32 {
		return ErrInvalid
	}
	if message.Expires <= time.Now().Unix() {
		return ErrExpired
	}
	var wrapper delivery
	if open(message.Body, message.ID, doorDelivery, h.Keys.Recipient, 1, &wrapper) == nil {
		body, digest, err := h.verifyRequest(ctx, message, wrapper)
		if err != nil {
			return err
		}
		if err := h.Journal.accept(body.Authorization.RequestID, digest, message); err != nil {
			return err
		}
		if body.Authorization.Offer != "" {
			return h.fulfillPurchase(ctx, wrapper, body, digest)
		}
		return nil
	}
	if h.Audit != nil {
		var change signedRotation
		if open(message.Body, message.ID, auditRotatePurpose, h.Keys.Recipient, 1, &change) == nil {
			return h.rotateAudit(ctx, message, change)
		}
	}
	var signed signedDecision
	if err := open(message.Body, message.ID, decisionPurpose, h.Keys.Recipient, 1, &signed); err != nil {
		return err
	}
	if message.ID != decisionID(signed.Record) || message.Expires != signed.Record.Deadline {
		return ErrInvalid
	}
	return h.decide(ctx, signed)
}

func (h Host) verifyRequest(ctx context.Context, message mailbox.Message, wrapper delivery) (doorPayload, common.Hash, error) {
	m := wrapper.Manifest.Record
	var body doorPayload
	if m.Door.Account != h.Keys.Account.Bech32 ||
		message.ID != recordID(doorDelivery, m.DoorID, m.RequestID, "") || message.Expires != m.Deadline ||
		!checkedDigest(wrapper.Inner, m.DoorEnvelope) ||
		open(wrapper.Inner, message.ID, doorInner, h.Keys.Recipient, 1, &body) != nil {
		return body, common.Hash{}, ErrInvalid
	}
	a := body.Authorization
	if body.ReplyRoute != a.Requester.Account || (body.SSH == ([32]byte{})) != (a.Offer != "") ||
		!h.validX25519(body.WireGuard[:]) ||
		qoreseal.ValidateMlkemPublicKey(body.Reply.MlkemPublicKey) != nil ||
		!h.validX25519(body.Reply.X25519PublicKey) || bytes.Equal(body.WireGuard[:], body.Reply.X25519PublicKey) ||
		checkedDigest(body.Reply.MlkemPublicKey, a.Requester.KEM) || checkedDigest(body.Reply.X25519PublicKey, a.Requester.X25519) {
		return body, common.Hash{}, ErrInvalid
	}
	for _, actor := range append(slices.Clone(m.Approvers), a.Door) {
		if checkedDigest(body.Reply.MlkemPublicKey, actor.KEM) || checkedDigest(body.Reply.X25519PublicKey, actor.X25519) {
			return body, common.Hash{}, ErrInvalid
		}
	}
	card, err := h.Authority.Door(ctx, m.Door.Account)
	if err != nil {
		return body, common.Hash{}, err
	}
	if err := a.valid(card.Details, time.Now().Unix()); err != nil {
		return body, common.Hash{}, err
	}
	actor, err := CardBinding(card)
	if err != nil || actor != localBinding(h.Keys) {
		return body, common.Hash{}, ErrInvalid
	}
	if _, err := verifyManifest(ctx, h.Authority, card, actor, a, wrapper.Manifest); err != nil {
		return body, common.Hash{}, err
	}
	digest, err := protocol.Digest(wrapper.Manifest)
	return body, digest, err
}

func (h Host) validX25519(public []byte) bool {
	shared, err := qoreseal.X25519Agree(h.Keys.Recipient.X25519SecretKey, public)
	clear(shared)
	return err == nil
}

func (h Host) decide(ctx context.Context, signed signedDecision) error {
	d := signed.Record
	a := d.Authorization
	if a.Offer != "" {
		return ErrInvalid
	}
	now := time.Now().Unix()
	if a.Door.Account != h.Keys.Account.Bech32 || d.Deadline != a.Deadline || d.Issued >= d.Deadline ||
		d.Issued < a.Created-5 || d.Issued > now+5 || (d.Outcome != Authorized && d.Outcome != Denied) ||
		d.Reviewed == (common.Hash{}) {
		return ErrInvalid
	}
	item, err := h.Journal.get(a.RequestID)
	if err != nil {
		return err
	}
	if item.Manifest != d.Manifest {
		return ErrInvalid
	}
	digest, err := protocol.Digest(signed)
	if err != nil {
		return err
	}
	if item.Outcome != Pending {
		if item.Decision == digest && item.Outcome == d.Outcome {
			return nil
		}
		return ErrInvalid
	}
	if item.Deadline <= now {
		return ErrExpired
	}
	var wrapper delivery
	if item.Delivery == nil {
		return errors.New("Door journal is missing a pending delivery")
	}
	if err := open(item.Delivery.Body, item.Delivery.ID, doorDelivery, h.Keys.Recipient, 1, &wrapper); err != nil {
		return err
	}
	manifestHash, err := protocol.Digest(wrapper.Manifest)
	if err != nil {
		return err
	}
	var body doorPayload
	if manifestHash != d.Manifest ||
		!checkedDigest(wrapper.Inner, d.DoorEnvelope) ||
		open(wrapper.Inner, item.Delivery.ID, doorInner, h.Keys.Recipient, 1, &body) != nil ||
		body.Authorization != a || d.DoorEnvelope != wrapper.Manifest.Record.DoorEnvelope {
		return ErrInvalid
	}
	card, err := h.Authority.Door(ctx, a.Door.Account)
	if err != nil {
		return err
	}
	if err := a.valid(card.Details, time.Now().Unix()); err != nil {
		return err
	}
	expected, eligible := approverBinding(wrapper.Manifest.Record, d.Approver.Account)
	if !eligible || expected != d.Approver || !slices.Contains(card.Details.Policy.Approvers, d.Approver.Account) {
		return ErrInvalid
	}
	currentDoor, err := CardBinding(card)
	if err != nil || currentDoor != localBinding(h.Keys) {
		return ErrInvalid
	}
	session := SessionReference(a.DoorID, a.RequestID)
	checkPolicy := func(ctx context.Context) error {
		now := time.Now().Unix()
		if now >= card.Details.Expires {
			return ErrPolicy
		}
		if err := a.valid(card.Details, now); err != nil {
			return err
		}
		allowed, err := h.Authority.CanAdmit(ctx, card.Details, session)
		if err != nil {
			return err
		}
		if !allowed {
			return ErrInvalid
		}
		return nil
	}
	verify := func(ctx context.Context, fresh bool) (Actor, Actor, error) {
		var requester, reviewer Actor
		group, call := errgroup.WithContext(ctx)
		group.Go(func() error {
			var err error
			requester, err = verifyManifest(call, h.Authority, card, currentDoor, a, wrapper.Manifest)
			return err
		})
		group.Go(func() error {
			var err error
			reviewer, err = h.Authority.Actor(call, card.Details, d.Approver.Account, d.ApproverCard)
			if err != nil {
				return err
			}
			if reviewer.Binding != d.Approver ||
				protocol.Verify(d.Approver.Account, reviewer.Signing, decisionPurpose, d, signed.Signature) != nil {
				return ErrInvalid
			}
			return nil
		})
		if fresh {
			group.Go(func() error {
				current, err := h.Authority.Door(call, a.Door.Account)
				if err != nil {
					return err
				}
				if err := a.valid(current.Details, time.Now().Unix()); err != nil {
					return err
				}
				binding, err := CardBinding(current)
				if err != nil || binding != currentDoor {
					return ErrInvalid
				}
				return nil
			})
		}
		if err := group.Wait(); err != nil {
			return Actor{}, Actor{}, err
		}
		if d.Outcome == Authorized {
			return requester, reviewer, checkPolicy(ctx)
		}
		return requester, reviewer, nil
	}
	requester, reviewer, err := verify(ctx, false)
	if err != nil {
		return err
	}
	if d.Outcome == Authorized && h.SSH != nil {
		if h.publish == nil {
			return errors.New("the Door cannot publish a private connection response")
		}
		recipients := []sessionRecipient{
			{requester.Binding.Account, requester.Recipient},
			{reviewer.Binding.Account, reviewer.Recipient},
		}
		owner := card.Details.Owner
		if h.lookup != nil && owner != requester.Binding.Account && owner != reviewer.Binding.Account {
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
		return h.provision(ctx, body, manifestHash, digest, session, common.Hash{}, targets, func(ctx context.Context) error {
			_, _, err := verify(ctx, true)
			return err
		}, checkPolicy)
	}
	notice, err := h.notice(a, body, d.Outcome, manifestHash, digest, session, nil)
	if err != nil {
		return err
	}
	_, err = h.Journal.decide(a.RequestID, manifestHash, digest, d.Outcome, &notice, nil, nil)
	return err
}

func (h Host) notice(a authorization, body doorPayload, outcome Outcome, manifest, decision, session common.Hash, conn *connection) (mailbox.Message, error) {
	auth, err := protocol.Digest(a)
	if err != nil {
		return mailbox.Message{}, err
	}
	reply, err := protocol.Digest(body.Reply)
	if err != nil {
		return mailbox.Message{}, err
	}
	record := status{
		Authorization: auth, Manifest: manifest, Decision: decision, RequestID: a.RequestID,
		Session: session, Door: a.Door, Reply: reply, Outcome: outcome, Issued: time.Now().Unix(), Deadline: a.Deadline, Connection: conn,
	}
	purpose := statusPurpose
	id := recordID(statusPurpose, a.DoorID, a.RequestID, "")
	expires := a.Deadline + 120
	if conn != nil {
		purpose, id = connectionPurpose, connectionID(session)
		expires = min(conn.Deadline, expires)
	}
	signature, err := protocol.Sign(h.Keys, purpose, record)
	if err != nil {
		return mailbox.Message{}, err
	}
	sealed, err := seal(signedStatus{record, signature}, id, purpose, body.Reply)
	return mailbox.Message{Route: body.ReplyRoute, ID: id, Expires: expires, Body: sealed}, err
}

func (h Host) Poll(ctx context.Context, relay *mailbox.Client) error {
	h.publish, h.lookup = relay.Send, relay.Card
	if err := h.Journal.expire(time.Now().Unix()); err != nil {
		return err
	}
	messages, err := relay.Inbox(ctx)
	if err != nil {
		return err
	}
	var deferred error
	for _, message := range messages {
		call, cancel := context.WithTimeout(ctx, 90*time.Second)
		err := h.Receive(call, message)
		cancel()
		switch {
		case err == nil, errors.Is(err, ErrInvalid), errors.Is(err, ErrExpired), errors.Is(err, ErrPolicy):
			if err := relay.Ack(ctx, message.ID); err != nil {
				deferred = err
			}
		case errors.Is(err, ErrPending):
			// An Entry Pass can arrive before the independently delivered Door request.
		default:
			deferred = err
		}
	}
	pending, err := h.Journal.notices()
	if err != nil {
		return err
	}
	for _, queued := range pending {
		if queued.message.Expires <= time.Now().Unix() {
			continue
		}
		if err := relay.Send(ctx, queued.message); err != nil {
			deferred = err
			continue
		}
		if err := h.Journal.delivered(queued.request, queued.message.ID); err != nil {
			return err
		}
	}
	if err := h.deliverSessionStatus(ctx, relay.Send); err != nil {
		deferred = err
	}
	return deferred
}
