package chain

import (
	"context"
	"errors"
	"fmt"
	"math/big"
	"time"

	"knock/internal/identity"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	qoresign "github.com/qorechain/qoresign/go"
)

type Policy struct {
	Commitment         common.Hash
	Enabled            bool
	ApproversCanRevoke bool
	Approvers          []common.Address
}

type Door struct {
	Owner   common.Address
	Account common.Address
	Version uint64
	Policy  Policy
}

type Registry struct {
	Address  common.Address `json:"address"`
	CodeHash common.Hash    `json:"codeHash"`
}

const (
	registerOwner uint8 = 1
	registerDoor  uint8 = 2
	updatePolicy  uint8 = 3
	revokeSession uint8 = 4
)

func (e *EVM) registryBlock(ctx context.Context, registry Registry) (common.Hash, error) {
	if registry.Address == (common.Address{}) || registry.CodeHash == (common.Hash{}) {
		return common.Hash{}, errors.New("a pinned registry address and code hash are required")
	}
	block, err := e.finalized(ctx)
	if err != nil {
		return common.Hash{}, err
	}
	hash, err := e.codeHash(ctx, registry.Address, block.Hash)
	if err != nil {
		return common.Hash{}, err
	}
	if hash != registry.CodeHash {
		return common.Hash{}, errors.New("registry bytecode does not match the pinned hash")
	}
	return block.Hash, nil
}

func (e *EVM) read(ctx context.Context, registry Registry, block common.Hash, method string, args ...any) ([]any, error) {
	data, err := e.abi.Pack(method, args...)
	if err != nil {
		return nil, err
	}
	raw, err := e.client.CallContractAtHash(ctx, ethereum.CallMsg{To: &registry.Address, Data: data}, block)
	if err != nil {
		return nil, fmt.Errorf("read registry %s: %w", method, err)
	}
	return e.abi.Unpack(method, raw)
}

func (e *EVM) Door(ctx context.Context, registry Registry, id common.Hash) (Door, common.Hash, error) {
	block, err := e.registryBlock(ctx, registry)
	if err != nil {
		return Door{}, common.Hash{}, err
	}
	values, err := e.read(ctx, registry, block, "door", id)
	if err != nil {
		return Door{}, common.Hash{}, err
	}
	// The tuple shape comes from the pinned registry ABI and is checked during ABI decoding.
	door := *abi.ConvertType(values[0], new(Door)).(*Door)
	return door, block, nil
}

func (e *EVM) Revoked(ctx context.Context, registry Registry, doorID, session common.Hash) (bool, error) {
	block, err := e.registryBlock(ctx, registry)
	if err != nil {
		return false, err
	}
	values, err := e.read(ctx, registry, block, "revoked", doorID, session)
	if err != nil {
		return false, err
	}
	return values[0].(bool), nil
}

func (e *EVM) authorization(
	ctx context.Context, registry Registry, block common.Hash, keys *identity.Keys,
	action uint8, doorID, details common.Hash, deadline uint64,
) (*big.Int, []byte, error) {
	if err := e.Binding(ctx, keys.Account, keys.Signing.PublicKey, block); err != nil {
		return nil, nil, err
	}
	account := common.BytesToAddress(keys.Account.Bytes)
	values, err := e.read(ctx, registry, block, "nonces", account)
	if err != nil {
		return nil, nil, err
	}
	nonce := values[0].(*big.Int)
	local, err := e.authorizationBytes(registry.Address, action, account, doorID, details, nonce, deadline)
	if err != nil {
		return nil, nil, err
	}
	remote, err := e.read(ctx, registry, block, "authorizationMessage", action, account, doorID, details, nonce, deadline)
	if err != nil {
		return nil, nil, err
	}
	if string(local) != string(remote[0].([]byte)) {
		return nil, nil, errors.New("registry authorization bytes differ from local encoding")
	}
	signature, err := qoresign.PqSign(keys.Signing.SecretKey, local, true)
	return nonce, signature, err
}

func (e *EVM) authorizationBytes(
	registry common.Address, action uint8, account common.Address, doorID, details common.Hash,
	nonce *big.Int, deadline uint64,
) ([]byte, error) {
	args := e.abi.Methods["authorizationMessage"].Inputs
	format := abi.Arguments{args[2], args[4], args[1], args[0], args[1], args[2], args[3], args[4], args[5]}
	return format.Pack(crypto.Keccak256Hash([]byte("knock-registry-v1")), big.NewInt(EVMID), registry, action,
		account, doorID, details, nonce, deadline)
}

func (e *EVM) RegisterDoor(
	ctx context.Context, registry Registry, id common.Hash, policy Policy, owner, door *identity.Keys, report func(string),
) error {
	block, err := e.registryBlock(ctx, registry)
	if err != nil {
		return err
	}
	ownerAddress := common.BytesToAddress(owner.Account.Bytes)
	doorAddress := common.BytesToAddress(door.Account.Bytes)
	args := e.abi.Methods["register"].Inputs
	version := e.abi.Methods["updatePolicy"].Inputs[1]
	data, err := (abi.Arguments{args[1], args[2], version, args[3]}).Pack(ownerAddress, doorAddress, uint64(1), policy)
	if err != nil {
		return err
	}
	details := crypto.Keccak256Hash(data)
	deadline := uint64(time.Now().Add(2 * time.Minute).Unix())
	ownerNonce, ownerSignature, err := e.authorization(ctx, registry, block, owner, registerOwner, id, details, deadline)
	if err != nil {
		return err
	}
	doorNonce, doorSignature, err := e.authorization(ctx, registry, block, door, registerDoor, id, details, deadline)
	if err != nil {
		return err
	}
	return e.mutate(ctx, registry, owner, report, "register", id, ownerAddress, doorAddress,
		policy, ownerNonce, doorNonce, deadline, ownerSignature, doorSignature)
}

func (e *EVM) UpdatePolicy(
	ctx context.Context, registry Registry, id common.Hash, version uint64, policy Policy, owner *identity.Keys, report func(string),
) error {
	current, block, err := e.Door(ctx, registry, id)
	if err != nil {
		return err
	}
	if current.Version == 0 || current.Owner != common.BytesToAddress(owner.Account.Bytes) || version != current.Version+1 {
		return errors.New("policy update requires the registered owner and the next version")
	}
	data, err := e.abi.Methods["updatePolicy"].Inputs[1:3].Pack(version, policy)
	if err != nil {
		return err
	}
	deadline := uint64(time.Now().Add(2 * time.Minute).Unix())
	nonce, signature, err := e.authorization(ctx, registry, block, owner, updatePolicy, id, crypto.Keccak256Hash(data), deadline)
	if err != nil {
		return err
	}
	return e.mutate(ctx, registry, owner, report, "updatePolicy", id, version, policy, nonce, deadline, signature)
}

func (e *EVM) Revoke(
	ctx context.Context, registry Registry, id, session common.Hash, signer *identity.Keys, report func(string),
) error {
	current, block, err := e.Door(ctx, registry, id)
	if err != nil {
		return err
	}
	if current.Version == 0 || session == (common.Hash{}) {
		return errors.New("revocation requires a registered Door and a session reference")
	}
	address := common.BytesToAddress(signer.Account.Bytes)
	authorized := address == current.Owner
	if current.Policy.ApproversCanRevoke {
		for _, approver := range current.Policy.Approvers {
			authorized = authorized || approver == address
		}
	}
	if !authorized {
		return errors.New("the current Door policy does not allow this account to revoke")
	}
	args := e.abi.Methods["revoke"].Inputs
	data, err := (abi.Arguments{args[2], args[1]}).Pack(current.Version, session)
	if err != nil {
		return err
	}
	deadline := uint64(time.Now().Add(2 * time.Minute).Unix())
	nonce, signature, err := e.authorization(ctx, registry, block, signer, revokeSession, id, crypto.Keccak256Hash(data), deadline)
	if err != nil {
		return err
	}
	if err := e.mutate(ctx, registry, signer, report, "revoke", id, session, current.Version, address, nonce, deadline, signature); err != nil {
		return err
	}
	revoked, err := e.Revoked(ctx, registry, id, session)
	if err != nil {
		return err
	}
	if !revoked {
		return errors.New("revocation is absent from the finalized registry state")
	}
	return nil
}

func (e *EVM) mutate(
	ctx context.Context, registry Registry, keys *identity.Keys, report func(string), method string, args ...any,
) error {
	data, err := e.abi.Pack(method, args...)
	if err != nil {
		return err
	}
	from := common.BytesToAddress(keys.Account.Bytes)
	estimate, err := e.client.EstimateGas(ctx, ethereum.CallMsg{From: from, To: &registry.Address, Data: data})
	if err != nil {
		return fmt.Errorf("registry refused %s preflight: %w", method, err)
	}
	if estimate == 0 || estimate > 600000 {
		return errors.New("registry gas estimate exceeds the testnet limit")
	}
	receipt, err := e.send(ctx, keys, &registry.Address, data, estimate+estimate/5, report)
	if err == nil {
		report("EVM transaction confirmed " + receipt.TxHash.Hex())
	}
	return err
}
