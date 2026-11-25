package admission

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"knock/internal/lease"
	"knock/internal/mailbox"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	"golang.org/x/crypto/ssh"
)

func TestConnectionResponseBindsLeaseAndRequesterKeys(t *testing.T) {
	h := newHarness(t, 1)
	now := time.Now()
	r, _ := h.request(t, now)
	defer r.Clear()
	a := r.auth
	session := SessionReference(a.DoorID, a.RequestID)
	wg, err := ecdh.X25519().NewPrivateKey(r.wg)
	if err != nil {
		t.Fatal(err)
	}
	body := doorPayload{Reply: qoreseal.RecipientOf(r.reply), ReplyRoute: a.Requester.Account}
	sshKey := r.ssh.Public().(ed25519.PublicKey)
	sshPublic, err := ssh.NewPublicKey(sshKey)
	if err != nil {
		t.Fatal(err)
	}
	_, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := ssh.NewSignerFromKey(caPrivate)
	if err != nil {
		t.Fatal(err)
	}
	leaseDeadline := now.Unix() + int64(a.Seconds)
	principal := "knock-" + hex.EncodeToString(session[:])
	cert := &ssh.Certificate{
		Key: sshPublic, CertType: ssh.UserCert, KeyId: principal, ValidPrincipals: []string{principal},
		ValidAfter: uint64(now.Unix() - 5), ValidBefore: uint64(leaseDeadline),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"source-address": lease.ClientIP + "/32"}},
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	connection := connection{Issued: now.Unix(), Deadline: leaseDeadline, ClientWireGuard: [32]byte(wg.PublicKey().Bytes()),
		Data: lease.Connection{Endpoint: "198.18.0.1:48001", ServerKey: [32]byte{1}, PSK: [32]byte{2},
			HostKey: ca.PublicKey().Marshal(), Certificate: cert.Marshal()},
	}
	makeMessage := func() mailbox.Message {
		t.Helper()
		m, err := h.host.notice(a, body, Ready, r.manifest, common.Hash{9}, session, &connection)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	message := makeMessage()
	response, err := r.ReadResponse(t.Context(), h.authority, message)
	if err != nil || response.Outcome != Ready || response.Deadline.Unix() != leaseDeadline || response.Connection.PSK != connection.Data.PSK {
		t.Fatalf("valid reply failed: %v", err)
	}
	for _, unrelated := range []qoreseal.SealKeyPair{h.requester.Recipient, h.approvers[0].Recipient, h.host.Keys.Recipient, keys(t, 12).Recipient} {
		var s signedStatus
		if open(message.Body, message.ID, connectionPurpose, unrelated, 1, &s) == nil {
			t.Fatal("unrelated recipient opened the connection response")
		}
	}
	wrongLifetime := message
	wrongLifetime.Expires++
	if _, err := r.ReadResponse(t.Context(), h.authority, wrongLifetime); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted substituted delivery expiry: %v", err)
	}
	connection.ClientWireGuard[0] ^= 1
	if _, err := r.ReadResponse(t.Context(), h.authority, makeMessage()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted substituted WireGuard key: %v", err)
	}
	connection.ClientWireGuard[0] ^= 1
	connection.Deadline++
	if _, err := r.ReadResponse(t.Context(), h.authority, makeMessage()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted extended lease: %v", err)
	}
	connection.Deadline--
	cert.ValidPrincipals = []string{"wrong-principal"}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	connection.Data.Certificate = cert.Marshal()
	if _, err := r.ReadResponse(t.Context(), h.authority, makeMessage()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("accepted wrong SSH principal: %v", err)
	}
}

func TestLeaseReservationPersistsAndCannotReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "private", "db")
	j, db := journalAt(t, path)
	request, digest, decision, session := common.Hash{1}, common.Hash{2}, common.Hash{3}, common.Hash{4}
	now := time.Now()
	if err := j.accept(request, digest, mailbox.Message{Expires: now.Add(time.Minute).Unix()}); err != nil {
		t.Fatal(err)
	}
	record := leaseRecord{ID: session, Issued: now.Unix(), Deadline: now.Add(2 * time.Minute).Unix(), State: lease.Reserved}
	if accepted, err := j.decide(request, digest, decision, Authorized, nil, &record); err != nil || !accepted {
		t.Fatalf("reservation failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	j, _ = journalAt(t, path)
	if accepted, err := j.decide(request, digest, decision, Authorized, nil, &record); err != nil || accepted {
		t.Fatalf("duplicate decision was actionable: %v", err)
	}
	item, err := j.get(request)
	if err != nil || item.Lease == nil || *item.Lease != record || item.Delivery != nil {
		t.Fatalf("reservation did not survive reopen: %v", err)
	}
	if err := j.updateLease(request, lease.Provisioning, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := j.observeLease(session, lease.Closed); err != nil {
		t.Fatal(err)
	}
	if err := j.updateLease(request, lease.Ready, nil); err == nil {
		t.Fatal("closed grant became ready again")
	}
}
