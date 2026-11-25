package chain

import (
	"bytes"
	"context"
	"encoding/json"
	"math/big"
	"os"
	"testing"
	"time"

	"knock/internal/identity"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rpc"
	qoresign "github.com/qorechain/qoresign/go"
)

func TestDianaMutationGuards(t *testing.T) {
	path := os.Getenv("KNOCK_DIANA_FIXTURE")
	if path == "" {
		t.Skip("set KNOCK_DIANA_FIXTURE for the disposable Diana lab")
	}
	var fixture struct {
		Config   string
		Profiles map[string]struct {
			Profile    string
			Credential string
		}
		RevocationTransaction common.Hash
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	raw, err = os.ReadFile(fixture.Config)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Registry Registry
		DoorID   common.Hash
	}
	if err := json.Unmarshal(raw, &config); err != nil {
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
	owner := load("owner")
	outsider := load("outsider")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()
	e, err := Connect(ctx, Diana())
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	state, block, err := e.Door(ctx, config.Registry, config.DoorID)
	if err != nil {
		t.Fatal(err)
	}
	if state.Version < 2 {
		t.Fatal("fixture has no confirmed policy update")
	}
	check := func(from common.Address, method string, want string, args ...any) {
		t.Helper()
		payload, err := e.abi.Pack(method, args...)
		if err != nil {
			t.Fatal(err)
		}
		_, err = e.client.CallContractAtHash(ctx, ethereum.CallMsg{From: from, To: &config.Registry.Address, Data: payload}, block)
		data, ok := err.(rpc.DataError)
		if !ok {
			t.Fatalf("expected %s from Diana, got %v", want, err)
		}
		dataHex, ok := data.ErrorData().(string)
		known := e.abi.Errors[want]
		selector := known.ID[:4]
		if !ok || dataHex != hexutil.Encode(selector) {
			t.Fatalf("expected %s, got %v", want, err)
		}
	}
	next := state.Policy
	next.Commitment[0] ^= 1
	version := state.Version + 1
	encoded, err := e.abi.Methods["updatePolicy"].Inputs[1:3].Pack(version, next)
	if err != nil {
		t.Fatal(err)
	}
	details := crypto.Keccak256Hash(encoded)
	deadline := uint64(time.Now().Add(3 * time.Minute).Unix())
	nonce, good, err := e.authorization(ctx, config.Registry, block, owner, updatePolicy, config.DoorID, details, deadline)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := e.authorizationBytes(config.Registry.Address, updatePolicy, state.Owner, config.DoorID, details, nonce, deadline)
	if err != nil {
		t.Fatal(err)
	}
	classical, err := qoresign.ClassicalSign(owner.Classical, msg)
	if err != nil {
		t.Fatal(err)
	}
	check(state.Owner, "updatePolicy", "InvalidSignature", config.DoorID, version, next, nonce, deadline, classical)
	wrong, err := qoresign.PqSign(outsider.Signing.SecretKey, msg, true)
	if err != nil {
		t.Fatal(err)
	}
	check(common.BytesToAddress(outsider.Account.Bytes), "updatePolicy", "InvalidSignature", config.DoorID, version, next, nonce, deadline, wrong)
	altered := next
	altered.Commitment[1] ^= 1
	check(state.Owner, "updatePolicy", "InvalidSignature", config.DoorID, version, altered, nonce, deadline, good)
	earlier := new(big.Int).Sub(nonce, big.NewInt(1))
	check(state.Owner, "updatePolicy", "InvalidNonce", config.DoorID, version, next, earlier, deadline, good)
	check(state.Owner, "updatePolicy", "Expired", config.DoorID, version, next, nonce, uint64(1), good)

	var actual struct {
		Input hexutil.Bytes
	}
	if err := e.client.Client().CallContext(ctx, &actual, "eth_getTransactionByHash", fixture.RevocationTransaction); err != nil {
		t.Fatal(err)
	}
	method := e.abi.Methods["revoke"]
	if len(actual.Input) < 4 || !bytes.Equal(actual.Input[:4], method.ID) {
		t.Fatal("fixture is missing the actual Diana revocation call")
	}
	replay, err := method.Inputs.Unpack(actual.Input[4:])
	if err != nil {
		t.Fatal(err)
	}
	ref := *abi.ConvertType(replay[1], new(common.Hash)).(*common.Hash)
	revoked, err := e.Revoked(ctx, config.Registry, config.DoorID, ref)
	if err != nil || !revoked {
		t.Fatalf("committed revocation missing: %v", err)
	}
	check(state.Owner, "revoke", "AlreadyRevoked", replay...)
}
