package mailbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knock/internal/chain"
	"knock/internal/identity"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
)

const origin = "http://127.0.0.1:8180"

type testRegistry map[string][]byte

func (r testRegistry) Head(context.Context) (uint64, error) { return 1, nil }
func (r testRegistry) SigningKey(_ context.Context, account string) ([]byte, error) {
	if key := r[account]; key != nil {
		return key, nil
	}
	return nil, errors.New("unregistered identity")
}
func (r testRegistry) Recipient(context.Context, qoreseal.RecipientCard, string) (qoreseal.SealRecipient, error) {
	return qoreseal.SealRecipient{}, errors.New("card is unverified")
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (rr roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return rr(req) }

func transport(s *Server) roundTripFunc {
	return func(req *http.Request) (*http.Response, error) {
		req.RemoteAddr = "127.0.0.1:31234"
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, req)
		return rec.Result(), nil
	}
}

func testIdentity(t *testing.T, seed byte) *identity.Keys {
	t.Helper()
	raw := bytes.Repeat([]byte{seed}, 32)
	key, err := qoresign.ClassicalKeyFromPrivate(raw, qoresign.EthSecp256k1)
	if err != nil {
		t.Fatal(err)
	}
	account, err := qoresign.AddressFromPublicKey(key.PublicKey, key.Type)
	if err != nil {
		t.Fatal(err)
	}
	pq, err := qoresign.PqKeyFromSeed(raw)
	if err != nil {
		t.Fatal(err)
	}
	recipient, err := qoreseal.SealKeysFromSeed(raw)
	if err != nil {
		t.Fatal(err)
	}
	keys := &identity.Keys{Account: account, Classical: key, Signing: pq, Recipient: recipient}
	t.Cleanup(keys.Clear)
	return keys
}

func TestMailboxDeliveryAuthenticationRetentionAndFailure(t *testing.T) {
	const plaintext = "isolated plaintext fixture"
	path := filepath.Join(t.TempDir(), "private", "db")
	requester, door, outsider := testIdentity(t, 1), testIdentity(t, 2), testIdentity(t, 3)
	registry := testRegistry{}
	for _, profile := range []*identity.Keys{requester, door, outsider} {
		registry[profile.Account.Bech32] = profile.Signing.PublicKey
	}
	openDB := func() *Server {
		db, err := protocol.OpenState(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		server, err := NewServer(db, registry, origin)
		if err != nil {
			t.Fatal(err)
		}
		return server
	}
	server := openDB()
	client := func(keys *identity.Keys) *Client {
		c, err := NewClient(origin, keys)
		if err != nil {
			t.Fatal(err)
		}
		c.http.Transport = transport(server)
		return c
	}
	send, receive, wrong := client(requester), client(door), client(outsider)
	ctx := t.Context()
	id := common.Hash{1}
	body, err := qoreseal.Seal(qoreseal.SealArgs{
		ChainID: chain.NativeID, Purpose: "knock-mailbox-test", AAD: id[:], Anonymous: true,
		Recipients: []qoreseal.SealRecipient{qoreseal.RecipientOf(door.Recipient)}, Plaintext: []byte(plaintext),
	})
	if err != nil {
		t.Fatal(err)
	}
	message := Message{door.Account.Bech32, id, time.Now().Unix() + 300, body}
	plain := message
	plain.Body = []byte(plaintext)
	if err := send.Send(ctx, plain); err == nil {
		t.Fatal("Mailbox accepted plaintext")
	}
	for range 2 {
		if err := send.Send(ctx, message); err != nil {
			t.Fatal(err)
		}
	}
	if err := wrong.Ack(ctx, id); err != nil {
		t.Fatal(err)
	}
	if messages, err := wrong.Inbox(ctx); err != nil || len(messages) != 0 {
		t.Fatalf("wrong account saw the inbox: %v", err)
	}
	conflict := message
	conflict.Body = bytes.Clone(body)
	conflict.Body[len(body)-1] ^= 1
	if err := send.Send(ctx, conflict); err == nil {
		t.Fatal("same ID accepted different bytes")
	}

	receive.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/v1/inbox" {
			rec := httptest.NewRecorder()
			respond(rec, page{Messages: []Message{}})
			return rec.Result(), nil
		}
		return transport(server)(req)
	})
	if missing, err := receive.Inbox(ctx); err != nil || len(missing) != 0 {
		t.Fatalf("a dropped delivery became observable: %v", err)
	}

	receive.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		res, err := transport(server)(req)
		if err == nil && req.URL.Path == "/v1/inbox" {
			var batch page
			if err := decode(res.Body, &batch); err != nil {
				return nil, err
			}
			res.Body.Close()
			batch.Messages[0].Body[len(body)-1] ^= 1
			data, err := json.Marshal(batch)
			if err != nil {
				return nil, err
			}
			res.Body = io.NopCloser(bytes.NewReader(data))
		}
		return res, err
	})
	messages, err := receive.Inbox(ctx)
	if err != nil || len(messages) != 1 {
		t.Fatalf("tampered relay response: %v", err)
	}
	if _, err := qoreseal.Open(qoreseal.OpenArgs{
		ChainID: chain.NativeID, Purpose: "knock-mailbox-test", AAD: id[:], Keys: door.Recipient, Envelope: messages[0].Body,
	}); err == nil {
		t.Fatal("tampered ciphertext opened")
	}

	receive.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	timed, cancel := context.WithTimeout(ctx, 10*time.Millisecond)
	defer cancel()
	if _, err := receive.Inbox(timed); err == nil {
		t.Fatal("timed-out pull reported success")
	}
	receive.http.Transport = transport(server)
	messages, err = receive.Inbox(ctx)
	if err != nil || len(messages) != 1 || !bytes.Equal(messages[0].Body, body) {
		t.Fatalf("retry lost the delivery: %v", err)
	}

	var challenge Challenge
	_, err = send.request(ctx, http.MethodPost, "/v1/auth/challenge", struct{ Account string }{requester.Account.Bech32}, &challenge, "")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := protocol.Sign(requester, authPurpose, challenge)
	if err != nil {
		t.Fatal(err)
	}
	proof := proof{challenge, sig}
	var session session
	if _, err := send.request(ctx, http.MethodPost, "/v1/auth/session", proof, &session, ""); err != nil {
		t.Fatal(err)
	}
	if status, _ := send.request(ctx, http.MethodPost, "/v1/auth/session", proof, &session, ""); status != http.StatusUnauthorized {
		t.Fatalf("replayed challenge got HTTP %d", status)
	}
	if err := server.db.Close(); err != nil {
		t.Fatal(err)
	}
	server = openDB()
	send.http.Transport, receive.http.Transport = transport(server), transport(server)
	if messages, err := receive.Inbox(ctx); err != nil || len(messages) != 1 {
		t.Fatalf("unacknowledged inbox did not survive reopen: %v", err)
	}
	if err := receive.Ack(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := send.Send(ctx, message); err != nil {
		t.Fatal(err)
	}
	if messages, err := receive.Inbox(ctx); err != nil || len(messages) != 0 {
		t.Fatalf("retry resurrected acknowledged message: %v", err)
	}
	if err := server.prune(message.Expires); err != nil {
		t.Fatal(err)
	}
	if _, err := server.inbox(door.Account.Bech32, common.Hash{}, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}

	disk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(disk, []byte(plaintext)) || bytes.Contains(disk, []byte(session.Token)) {
		t.Fatal("plaintext or bearer token persisted by the Mailbox")
	}
}

func TestMailboxQueueAndPageBounds(t *testing.T) {
	db, err := protocol.OpenState(filepath.Join(t.TempDir(), "private", "db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server, err := NewServer(db, testRegistry{}, origin)
	if err != nil {
		t.Fatal(err)
	}
	account := testIdentity(t, 4).Account.Bech32
	now := time.Now().Unix()
	for i := 1; i <= MaxInbox+1; i++ {
		code, err := server.send(account, Message{account, common.Hash{byte(i)}, now + 5, []byte{1}}, now)
		if err != nil {
			t.Fatal(err)
		}
		want := http.StatusNoContent
		if i > MaxInbox {
			want = http.StatusTooManyRequests
		}
		if code != want {
			t.Fatalf("delivery %d: HTTP %d, expected %d", i, code, want)
		}
	}
	var after common.Hash
	for i := range MaxInbox / PageSize {
		page, err := server.inbox(account, after, now)
		if err != nil || len(page.Messages) != PageSize || (i+1 < MaxInbox/PageSize) != (page.Next != nil) {
			t.Fatalf("page %d violated its bound or cursor: %v", i, err)
		}
		if page.Messages[0].ID[0] != byte(i*PageSize+1) {
			t.Fatalf("page %d resumed at the wrong ID", i)
		}
		if page.Next != nil {
			after = *page.Next
		}
	}
	if err := server.prune(now + 5); err != nil {
		t.Fatal(err)
	}
	pruned, err := server.inbox(account, common.Hash{}, now+5)
	if err != nil || len(pruned.Messages) != 0 || pruned.Next != nil {
		t.Fatalf("expired messages remained visible: %v", err)
	}
}
