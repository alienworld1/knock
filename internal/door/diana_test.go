package door

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"knock/internal/chain"
	"knock/internal/identity"

	qoreseal "github.com/qorechain/qoreseal/go"
)

func TestDianaVerifiedRecipient(t *testing.T) {
	path := os.Getenv("KNOCK_DIANA_FIXTURE")
	if path == "" {
		t.Skip("set KNOCK_DIANA_FIXTURE for the disposable Diana lab")
	}
	var fixture struct {
		Config   string `json:"config"`
		Profiles map[string]struct {
			Profile    string `json:"profile"`
			Credential string `json:"credential"`
		} `json:"profiles"`
		RevocationTransaction string `json:"revocationTransaction"`
	}
	if err := ReadConfig(path, &fixture); err != nil {
		t.Fatal(err)
	}
	config, err := LoadConfig(fixture.Config)
	if err != nil {
		t.Fatal(err)
	}
	load := func(role string) *identity.Keys {
		t.Helper()
		entry := fixture.Profiles[role]
		pass, err := os.ReadFile(entry.Credential)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(pass)
		keys, err := identity.Unlock(entry.Profile, pass)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(keys.Clear)
		return keys
	}
	doorKey := load("door")
	requester := load("requester")
	outsider := load("outsider")
	native := chain.Diana()
	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()
	evm, err := chain.Connect(ctx, native)
	if err != nil {
		t.Fatal(err)
	}
	defer evm.Close()
	card, err := ReadCard(config.Cards, config.Account)
	if err != nil {
		t.Fatal(err)
	}
	if err := card.Verify(ctx, native, evm, config.Registry, config.Account); err != nil {
		t.Fatal(err)
	}
	stale := card
	stale.Details.Expires = time.Now().Add(-time.Second).Unix()
	if err := stale.Verify(ctx, native, evm, config.Registry, config.Account); err == nil {
		t.Fatal("accepted expired Door Card")
	}
	mismatch := card
	mismatch.Details.SigningKey[0] ^= 1
	if err := mismatch.Verify(ctx, native, evm, config.Registry, config.Account); err == nil {
		t.Fatal("accepted mismatched signing key")
	}

	target, err := native.Recipient(ctx, card.Details.Recipient, config.Account)
	if err != nil {
		t.Fatal(err)
	}
	requesterCard, err := recipientCard(ctx, native, requester)
	if err != nil {
		t.Fatal(err)
	}
	other, err := native.Recipient(ctx, requesterCard, requester.Account.Bech32)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.Recipient(ctx, requesterCard, config.Account); err == nil {
		t.Fatal("accepted another account's recipient card")
	}
	altered := card.Details.Recipient
	altered.X25519PublicKey = requesterCard.X25519PublicKey
	if _, err := native.Recipient(ctx, altered, config.Account); err == nil {
		t.Fatal("accepted unsigned recipient key replacement")
	}

	const purpose = "knock-m1-probe"
	message := []byte("disposable registered-recipient round trip")
	aad := []byte("knock-m1-diana")
	seal := func(recipients ...qoreseal.SealRecipient) []byte {
		t.Helper()
		data, err := qoreseal.Seal(qoreseal.SealArgs{
			ChainID: chain.NativeID, Purpose: purpose, Mode: qoreseal.ModeHybrid,
			Recipients: recipients, AAD: aad, Plaintext: message,
		})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	assertOpen := func(data []byte, keys qoreseal.SealKeyPair, binding []byte, allow bool) {
		t.Helper()
		got, err := qoreseal.Open(qoreseal.OpenArgs{
			Envelope: data, Keys: keys, ChainID: chain.NativeID, Purpose: purpose, AAD: binding,
		})
		if allow && (err != nil || !bytes.Equal(got, message)) {
			t.Fatalf("registered recipient couldn't open: %v", err)
		}
		if !allow && err == nil {
			t.Fatal("unexpected recipient or context opened the envelope")
		}
	}
	group := seal(target, other)
	assertOpen(group, doorKey.Recipient, aad, true)
	assertOpen(group, requester.Recipient, aad, true)
	assertOpen(group, outsider.Recipient, aad, false)

	ephemeral, err := qoreseal.GenerateSealKeys()
	if err != nil {
		t.Fatal(err)
	}
	reply := seal(qoreseal.RecipientOf(ephemeral))
	assertOpen(reply, ephemeral, aad, true)
	assertOpen(reply, requester.Recipient, aad, false)
	assertOpen(reply, outsider.Recipient, aad, false)
	assertOpen(reply, ephemeral, []byte("another context"), false)
}
