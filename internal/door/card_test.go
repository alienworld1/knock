package door

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"knock/internal/chain"
	"knock/internal/identity"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
)

func testKeys(t *testing.T, seed byte) *identity.Keys {
	t.Helper()
	material := bytes.Repeat([]byte{seed}, 32)
	classical, err := qoresign.ClassicalKeyFromPrivate(material, qoresign.EthSecp256k1)
	if err != nil {
		t.Fatal(err)
	}
	account, err := qoresign.AddressFromPublicKey(classical.PublicKey, classical.Type)
	if err != nil {
		t.Fatal(err)
	}
	pq, err := qoresign.PqKeyFromSeed(material)
	if err != nil {
		t.Fatal(err)
	}
	seal, err := qoreseal.SealKeysFromSeed(material)
	if err != nil {
		t.Fatal(err)
	}
	return &identity.Keys{Account: account, Classical: classical, Signing: pq, Recipient: seal}
}

func TestDoorCardCanonicalSignature(t *testing.T) {
	keys := testKeys(t, 1)
	owner := testKeys(t, 2).Account.Bech32
	approver := testKeys(t, 3).Account.Bech32
	now := time.Unix(1795616080, 0).UTC()
	recipient, err := qoreseal.SignRecipientCard(qoreseal.SignRecipientCardArgs{
		ChainID: chain.NativeID, Address: keys.Account.Bech32, Keys: keys.Recipient,
		ClassicalKey: keys.Classical, PqKey: keys.Signing, IssuedAt: qoreseal.FormatIssuedAt(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	config := Config{
		Registry: chain.Registry{Address: common.Address{1}, CodeHash: common.Hash{2}}, DoorID: common.Hash{3},
		Policy: Policy{Version: 1, Enabled: true, MaxDurationSeconds: 900, Approvers: []string{approver}, Roles: []string{"logs"}},
	}
	card, err := NewCard(config, owner, keys, recipient, now)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := card.Encode()
	if err != nil {
		t.Fatal(err)
	}
	copy, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(append(wire, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
	record, err := copy.Details.signBytes()
	if err != nil {
		t.Fatal(err)
	}
	framed, err := qoresign.MessagePqSignBytes(chain.NativeID, record)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(framed)
	if got := hex.EncodeToString(digest[:]); got != "36cc4e3fdb7a44612588ff299f34d6fd90e300f6fcfa4ad56bbdba0e1930937b" {
		t.Fatalf("QoreSign framing vector: %s", got)
	}
	verify := qoresign.VerifyMessageOptions{
		ChainID: chain.NativeID, Signer: copy.Details.Account, Data: record,
		Signature: copy.Signature, PqPublicKey: keys.Signing.PublicKey,
	}
	if err := qoresign.VerifyMessage(verify); err != nil {
		t.Fatal(err)
	}
	copy.Details.Policy.Version++
	verify.Data, err = copy.Details.signBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := qoresign.VerifyMessage(verify); err == nil {
		t.Fatal("accepted changed policy")
	}
}

func TestAliasCannotSilentlyChange(t *testing.T) {
	directory := t.TempDir() + "/aliases"
	original := Alias{Account: testKeys(t, 1).Account.Bech32, SigningKey: common.Hash{1}}
	if err := SaveAlias(directory, "validator-ops", original); err != nil {
		t.Fatal(err)
	}
	changed := original
	changed.Account = testKeys(t, 2).Account.Bech32
	if err := SaveAlias(directory, "validator-ops", changed); err == nil {
		t.Fatal("changed the trusted account")
	}
	changed = original
	changed.SigningKey[0]++
	if err := SaveAlias(directory, "validator-ops", changed); err == nil {
		t.Fatal("changed the trusted signing key")
	}
	got, err := ReadAlias(directory, "validator-ops")
	if err != nil || got != original {
		t.Fatalf("stored alias: %+v, %v", got, err)
	}
}
