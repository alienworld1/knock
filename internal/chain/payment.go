package chain

import (
	"context"
	"errors"
	"math/big"
	"time"

	"knock/internal/identity"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

const (
	setOffer     uint8 = 5
	purchasePass uint8 = 6
	consumePass  uint8 = 7
)

type Offer struct {
	Id          common.Hash
	Version     uint64
	Duration    uint64
	Amount      *big.Int
	Beneficiary common.Address
}

func (o Offer) Matches(other Offer) bool {
	return o.Id == other.Id && o.Version == other.Version && o.Duration == other.Duration &&
		o.Beneficiary == other.Beneficiary && o.Amount != nil && other.Amount != nil && o.Amount.Cmp(other.Amount) == 0
}

type Purchase struct {
	DoorId     common.Hash
	Buyer      common.Address
	Offer      Offer
	RedeemBy   uint64
	SessionRef common.Hash
}

type TransactionState string

const (
	TransactionUnknown   TransactionState = "Unknown"
	TransactionPending   TransactionState = "Pending"
	TransactionReverted  TransactionState = "Reverted"
	TransactionConfirmed TransactionState = "Confirmed"
)

// PaymentReceipt distinguishes a finalized revert, a visible pending transaction and an unknown outcome.
func (e *EVM) PaymentReceipt(ctx context.Context, hash common.Hash) (TransactionState, error) {
	receipt, err := e.client.TransactionReceipt(ctx, hash)
	if errors.Is(err, ethereum.NotFound) {
		var observed *struct{ Hash common.Hash }
		if err := e.client.Client().CallContext(ctx, &observed, "eth_getTransactionByHash", hash); err != nil {
			return TransactionUnknown, err
		}
		if observed != nil && observed.Hash == hash {
			return TransactionPending, nil
		}
		return TransactionUnknown, nil
	}
	if err != nil {
		return TransactionUnknown, err
	}
	if receipt.TxHash != hash || receipt.BlockNumber == nil || !receipt.BlockNumber.IsUint64() {
		return TransactionUnknown, errors.New("Diana returned an invalid payment receipt")
	}
	final, err := e.finalized(ctx)
	if err != nil {
		return TransactionUnknown, err
	}
	if uint64(final.Number) < receipt.BlockNumber.Uint64() {
		return TransactionPending, nil
	}
	block, err := e.block(ctx, hexutil.EncodeBig(receipt.BlockNumber))
	if err != nil {
		return TransactionUnknown, err
	}
	if block.Hash != receipt.BlockHash {
		return TransactionUnknown, errors.New("payment receipt block does not match finalized Diana history")
	}
	if receipt.Status != types.ReceiptStatusSuccessful {
		return TransactionReverted, nil
	}
	return TransactionConfirmed, nil
}

func (e *EVM) OfferAt(ctx context.Context, registry Registry, block, door common.Hash) (Offer, error) {
	values, err := e.read(ctx, registry, block, "offers", door)
	if err != nil {
		return Offer{}, err
	}
	var offer Offer
	err = e.abi.Methods["offers"].Outputs.Copy(&offer, values)
	return offer, err
}

func (e *EVM) Payment(ctx context.Context, registry Registry, commitment common.Hash) (Purchase, error) {
	block, err := e.registryBlock(ctx, registry)
	if err != nil {
		return Purchase{}, err
	}
	return e.paymentAt(ctx, registry, block, commitment)
}

func (e *EVM) paymentAt(ctx context.Context, registry Registry, block, commitment common.Hash) (Purchase, error) {
	values, err := e.read(ctx, registry, block, "purchase", commitment)
	if err != nil {
		return Purchase{}, err
	}
	return *abi.ConvertType(values[0], new(Purchase)).(*Purchase), nil
}

func (e *EVM) SetOffer(ctx context.Context, registry Registry, door common.Hash, offer Offer, owner *identity.Keys, report func(string)) error {
	current, block, err := e.Door(ctx, registry, door)
	if err != nil {
		return err
	}
	if current.Version != offer.Version || current.Owner != common.BytesToAddress(owner.Account.Bytes) || len(current.Policy.Approvers) != 0 {
		return errors.New("setting an offer requires the owner and current metered policy")
	}
	existing, err := e.OfferAt(ctx, registry, block, door)
	if err != nil || offer.Matches(existing) {
		return err
	}
	encoded, err := e.abi.Methods["setOffer"].Inputs[1:2].Pack(offer)
	if err != nil {
		return err
	}
	deadline := uint64(time.Now().Add(2 * time.Minute).Unix())
	nonce, signature, err := e.authorization(ctx, registry, block, owner, setOffer, door, crypto.Keccak256Hash(encoded), deadline)
	if err != nil {
		return err
	}
	if err := e.mutate(ctx, registry, owner, report, "setOffer", door, offer, nonce, deadline, signature); err != nil {
		return err
	}
	block, err = e.registryBlock(ctx, registry)
	if err != nil {
		return err
	}
	stored, err := e.OfferAt(ctx, registry, block, door)
	if err == nil && !offer.Matches(stored) {
		err = errors.New("offer is absent from finalized registry state")
	}
	return err
}

func (e *EVM) Buy(ctx context.Context, registry Registry, door, commitment common.Hash, offer Offer, deadline uint64,
	buyer *identity.Keys, report func(string), record func(common.Hash) error,
) (common.Hash, error) {
	current, block, err := e.Door(ctx, registry, door)
	if err != nil {
		return common.Hash{}, err
	}
	actual, err := e.OfferAt(ctx, registry, block, door)
	if err != nil {
		return common.Hash{}, err
	}
	if !current.Policy.Enabled || len(current.Policy.Approvers) != 0 || current.Version != offer.Version || !offer.Matches(actual) {
		return common.Hash{}, errors.New("the confirmed quote is no longer current")
	}
	prior, err := e.paymentAt(ctx, registry, block, commitment)
	if err != nil {
		return common.Hash{}, err
	}
	if prior.Buyer != (common.Address{}) {
		return common.Hash{}, errors.New("registry already records this purchase")
	}
	args := e.abi.Methods["purchasePass"].Inputs
	terms, err := args[1:2].Pack(offer)
	if err != nil {
		return common.Hash{}, err
	}
	binding, err := (abi.Arguments{args[2], args[2]}).Pack(crypto.Keccak256Hash(terms), commitment)
	if err != nil {
		return common.Hash{}, err
	}
	nonce, signature, err := e.authorization(ctx, registry, block, buyer, purchasePass, door, crypto.Keccak256Hash(binding), deadline)
	if err != nil {
		return common.Hash{}, err
	}
	return e.transact(ctx, registry, buyer, offer.Amount, report, record, "purchasePass", door, offer, commitment, nonce, deadline, signature)
}

func (e *EVM) Consume(ctx context.Context, registry Registry, door, commitment, session common.Hash, version, deadline uint64,
	keys *identity.Keys, report func(string),
) error {
	block, err := e.registryBlock(ctx, registry)
	if err != nil {
		return err
	}
	args := e.abi.Methods["consumePass"].Inputs
	binding, err := args[1:4].Pack(version, commitment, session)
	if err != nil {
		return err
	}
	nonce, signature, err := e.authorization(ctx, registry, block, keys, consumePass, door, crypto.Keccak256Hash(binding), deadline)
	if err != nil {
		return err
	}
	return e.mutate(ctx, registry, keys, report, "consumePass", door, version, commitment, session, nonce, deadline, signature)
}
