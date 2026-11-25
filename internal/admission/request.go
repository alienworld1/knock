package admission

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"knock/internal/door"
	"knock/internal/identity"
	"knock/internal/mailbox"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
)

type Request struct {
	auth     authorization
	manifest common.Hash
	reply    qoreseal.SealKeyPair
	wg       []byte
	ssh      ed25519.PrivateKey
}

func (r *Request) ID() common.Hash     { return r.auth.RequestID }
func (r *Request) Deadline() time.Time { return time.Unix(r.auth.Deadline, 0) }

func (r *Request) Clear() {
	clear(r.reply.Seed)
	clear(r.reply.MlkemSecretKey)
	clear(r.reply.X25519SecretKey)
	clear(r.wg)
	clear(r.ssh)
}

func BuildRequest(ctx context.Context, authority Authority, relay *mailbox.Client, keys *identity.Keys,
	card door.Card, role string, duration time.Duration, reason string,
) (*Request, []mailbox.Message, error) {
	d := card.Details
	if !ValidReason(reason) || duration <= 0 || duration%time.Second != 0 ||
		!d.Policy.Enabled || !validScope(d, role, uint64(duration/time.Second)) {
		return nil, nil, errors.New("choose an advertised role, a permitted duration, and a printable reason")
	}
	if keys.Account.Bech32 == d.Account {
		return nil, nil, errors.New("use a requester identity separate from the Door")
	}
	requesterCard, err := RecipientCard(keys)
	if err != nil {
		return nil, nil, err
	}
	requester, err := authority.Actor(ctx, d, keys.Account.Bech32, requesterCard)
	if err != nil {
		return nil, nil, err
	}
	if !requester.Binding.Matches(keys) {
		return nil, nil, ErrInvalid
	}
	doorActor, err := authority.Actor(ctx, d, d.Account, d.Recipient)
	if err != nil {
		return nil, nil, err
	}
	if doorActor.Binding.Signing != d.SigningKey || doorActor.Binding.KEM != d.KEMKey {
		return nil, nil, ErrInvalid
	}
	approvers := make([]Binding, 0, len(d.Policy.Approvers))
	recipients := make([]qoreseal.SealRecipient, 0, len(d.Policy.Approvers))
	for _, account := range d.Policy.Approvers {
		if account == keys.Account.Bech32 || account == d.Account {
			return nil, nil, errors.New("use separate requester, approver, and Door identities")
		}
		publicCard, err := relay.Card(ctx, account)
		if err != nil {
			return nil, nil, fmt.Errorf("couldn't retrieve the recipient card for approver %s", account)
		}
		actor, err := authority.Actor(ctx, d, account, publicCard)
		if err != nil {
			return nil, nil, err
		}
		approvers = append(approvers, actor.Binding)
		recipients = append(recipients, actor.Recipient)
	}
	return buildRequest(keys, card, requesterCard, requester.Binding, doorActor, approvers, recipients, role, duration, reason, time.Now())
}

func buildRequest(keys *identity.Keys, card door.Card, requesterCard qoreseal.RecipientCard, requester Binding,
	doorActor Actor, approvers []Binding, recipients []qoreseal.SealRecipient, role string, duration time.Duration, reason string, now time.Time,
) (_ *Request, _ []mailbox.Message, err error) {
	d := card.Details
	a := authorization{
		Version: 1, Native: d.NativeChain, EVM: d.EVMChain, Registry: d.Registry.Address, DoorID: d.DoorID,
		Door: doorActor.Binding, Requester: requester, Policy: d.Policy.Version, PolicyHash: d.PolicyCommitment,
		Service: "ssh", Role: role, Seconds: uint64(duration / time.Second), Created: now.Unix(),
		Deadline: now.Add(RequestLifetime).Unix(),
	}
	rand.Read(a.RequestID[:])
	rand.Read(a.Salt[:])
	request := &Request{auth: a}
	defer func() {
		if err != nil {
			request.Clear()
		}
	}()
	request.reply, err = qoreseal.GenerateSealKeys()
	if err != nil {
		return nil, nil, err
	}
	wg, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	request.wg = wg.Bytes()
	ssh, secret, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	request.ssh = secret

	doorBody := doorPayload{
		Authorization: a, WireGuard: [32]byte(wg.PublicKey().Bytes()), SSH: [32]byte(ssh),
		Reply: qoreseal.RecipientOf(request.reply), ReplyRoute: a.Requester.Account,
	}
	id := func(purpose string) common.Hash { return recordID(purpose, a.DoorID, a.RequestID, "") }
	toDoor, err := seal(doorBody, id(doorDelivery), doorInner, doorActor.Recipient)
	if err != nil {
		return nil, nil, err
	}
	doorHash := sha256.Sum256(toDoor)
	// The Door knows the common authorization salt. Keep an independent salt
	// with the reason so the reviewed digest does not enable guesses by the Door.
	approval := approvalPayload{Authorization: a, DoorEnvelope: doorHash, Reason: reason}
	rand.Read(approval.ReviewSalt[:])
	toReview, err := seal(approval, id(reviewDelivery), reviewInner, recipients...)
	if err != nil {
		return nil, nil, err
	}
	authHash, err := protocol.Digest(a)
	if err != nil {
		return nil, nil, err
	}
	m := manifest{
		Authorization: authHash, RequestID: a.RequestID, Door: a.Door, DoorID: a.DoorID, Requester: a.Requester,
		RequesterCard: requesterCard, Approvers: approvers, DoorEnvelope: doorHash,
		ReviewEnvelope: sha256.Sum256(toReview), Deadline: a.Deadline, Mode: d.Mode,
	}
	sig, err := protocol.Sign(keys, manifestPurpose, m)
	if err != nil {
		return nil, nil, err
	}
	signed := signedManifest{m, sig}
	request.manifest, err = protocol.Digest(signed)
	if err != nil {
		return nil, nil, err
	}
	doorWrapper, err := seal(delivery{signed, toDoor}, id(doorDelivery), doorDelivery, doorActor.Recipient)
	if err != nil {
		return nil, nil, err
	}
	reviewWrapper, err := seal(delivery{signed, toReview}, id(reviewDelivery), reviewDelivery, recipients...)
	if err != nil {
		return nil, nil, err
	}
	messages := []mailbox.Message{{Route: d.Account, ID: id(doorDelivery), Expires: a.Deadline, Body: doorWrapper}}
	for _, actor := range approvers {
		messages = append(messages, mailbox.Message{
			Route: actor.Account, ID: id(reviewDelivery), Expires: a.Deadline, Body: reviewWrapper,
		})
	}
	return request, messages, nil
}

func (r *Request) StatusID() common.Hash {
	return recordID(statusPurpose, r.auth.DoorID, r.auth.RequestID, "")
}

func (r *Request) ReadStatus(ctx context.Context, authority Authority, message mailbox.Message) (Outcome, error) {
	a := r.auth
	id := r.StatusID()
	if message.ID != id || message.Route != a.Requester.Account {
		return "", ErrInvalid
	}
	var signed signedStatus
	if err := open(message.Body, id, statusPurpose, r.reply, 1, &signed); err != nil {
		return "", err
	}
	s := signed.Record
	reply, err := protocol.Digest(qoreseal.RecipientOf(r.reply))
	if err != nil {
		return "", err
	}
	digest, err := protocol.Digest(a)
	if err != nil {
		return "", err
	}
	if s.RequestID != a.RequestID || s.Session != SessionReference(a.DoorID, a.RequestID) ||
		s.Authorization != digest || s.Manifest != r.manifest || s.Decision == (common.Hash{}) ||
		s.Door != a.Door || s.Reply != reply || s.Deadline != a.Deadline || s.Issued < a.Created-5 ||
		s.Issued >= a.Deadline || s.Issued > time.Now().Unix()+5 || (s.Outcome != Authorized && s.Outcome != Denied) {
		return "", ErrInvalid
	}
	card, err := authority.Door(ctx, a.Door.Account)
	if err != nil {
		return "", err
	}
	if err := a.valid(card.Details, time.Now().Unix()); err != nil {
		return "", err
	}
	actor, err := authority.Actor(ctx, card.Details, a.Door.Account, card.Details.Recipient)
	if err != nil {
		return "", err
	}
	if actor.Binding != a.Door || protocol.Verify(a.Door.Account, actor.Signing, statusPurpose, s, signed.Signature) != nil {
		return "", ErrInvalid
	}
	return s.Outcome, nil
}
