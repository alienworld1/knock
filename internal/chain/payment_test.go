package chain

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"knock/internal/identity"

	"github.com/ethereum/go-ethereum/common"
)

func TestDianaPayment(t *testing.T) {
	fixture, credentials, pin := os.Getenv("KNOCK_DIANA_PROFILES"), os.Getenv("KNOCK_DIANA_CREDENTIALS"), os.Getenv("KNOCK_DIANA_PAYMENT_REGISTRY")
	if fixture == "" || credentials == "" || pin == "" {
		t.Skip("requires disposable Diana profiles, credentials, and a separately deployed registry")
	}
	raw, err := os.ReadFile(pin)
	if err != nil {
		t.Fatal(err)
	}
	var network struct{ Registry Registry }
	if err := json.Unmarshal(raw, &network); err != nil {
		t.Fatal(err)
	}
	load := func(role string) *identity.Keys {
		t.Helper()
		secret, err := os.ReadFile(filepath.Join(credentials, role+".cred"))
		if err != nil {
			t.Fatal(err)
		}
		defer clear(secret)
		keys, err := identity.Unlock(filepath.Join(fixture, role+".age"), secret)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(keys.Clear)
		return keys
	}
	owner, host, buyer, beneficiary := load("owner"), load("outsider"), load("requester"), load("approver")
	report := func(message string) { t.Log(message) }
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	client, err := Connect(ctx, Diana())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	block, err := client.registryBlock(ctx, network.Registry)
	if err != nil {
		t.Fatal(err)
	}
	hostAddress := common.BytesToAddress(host.Account.Bytes)
	values, err := client.read(ctx, network.Registry, block, "doorByAccount", hostAddress)
	if err != nil {
		t.Fatal(err)
	}
	id := common.Hash(values[0].([32]byte))
	commitment, session := common.Hash(randBytes(t)), common.Hash(randBytes(t))
	beneficiaryAddress := common.BytesToAddress(beneficiary.Account.Bytes)
	var offer Offer
	if id == (common.Hash{}) {
		id = common.Hash(randBytes(t))
		policy := Policy{Commitment: common.Hash(randBytes(t)), Enabled: true, Approvers: []common.Address{}}
		if err := client.RegisterDoor(ctx, network.Registry, id, policy, owner, host, report); err != nil {
			t.Fatal(err)
		}
		offer = Offer{Id: common.Hash(randBytes(t)), Version: 1, Duration: 60,
			Amount: big.NewInt(1_000_000_000_000), Beneficiary: beneficiaryAddress}
		if err := client.SetOffer(ctx, network.Registry, id, offer, owner, report); err != nil {
			t.Fatal(err)
		}
	} else {
		offer, err = client.OfferAt(ctx, network.Registry, block, id)
		if err != nil || offer.Id == (common.Hash{}) || offer.Beneficiary != beneficiaryAddress ||
			offer.Amount == nil || offer.Amount.Cmp(big.NewInt(1_000_000_000_000)) != 0 {
			t.Fatalf("registered fixture has no usable 1 uqor offer for the intended beneficiary: %v", err)
		}
	}
	before, err := client.client.BalanceAt(ctx, offer.Beneficiary, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := uint64(time.Now().Add(2 * time.Minute).Unix())
	var submitted common.Hash
	tx, err := client.Buy(ctx, network.Registry, id, commitment, offer, deadline, buyer, report, func(hash common.Hash) error {
		submitted = hash
		return nil
	})
	if err != nil || tx == (common.Hash{}) || tx != submitted {
		t.Fatalf("purchase %s: %v", submitted, err)
	}
	pass, err := client.Payment(ctx, network.Registry, commitment)
	if err != nil || pass.DoorId != id || pass.Buyer != common.BytesToAddress(buyer.Account.Bytes) ||
		!pass.Offer.Matches(offer) || pass.RedeemBy != deadline || pass.SessionRef != (common.Hash{}) {
		t.Fatalf("finalized purchase does not match: %v", err)
	}
	after, err := client.client.BalanceAt(ctx, offer.Beneficiary, nil)
	if err != nil || new(big.Int).Sub(after, before).Cmp(offer.Amount) != 0 {
		t.Fatalf("beneficiary did not receive the exact price: %v", err)
	}
	if _, err := client.Consume(ctx, network.Registry, id, commitment, session, offer.Version, deadline, host, report); err != nil {
		t.Fatal(err)
	}
	pass, err = client.Payment(ctx, network.Registry, commitment)
	if err != nil || pass.SessionRef != session {
		t.Fatalf("finalized consumption does not match: %v", err)
	}
	if _, err := client.Consume(ctx, network.Registry, id, commitment, session, offer.Version, deadline, host, report); err == nil {
		t.Fatal("registry allowed a second consumption")
	}
	if err := client.Revoke(ctx, network.Registry, id, session, owner, report); err != nil {
		t.Fatal(err)
	}
	t.Logf("finalized purchase %s, commitment %s, and revoked session %s", tx, commitment, session)
}

func randBytes(t *testing.T) [32]byte {
	t.Helper()
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return value
}
