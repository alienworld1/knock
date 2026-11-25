package chain

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"knock/internal/identity"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rpc"
	qoresign "github.com/qorechain/qoresign/go"
)

//go:embed registry.abi.json
var registryABI string

const pqcStatusABI = `[{"type":"function","name":"pqcKeyStatus","inputs":[{"type":"address"}],"outputs":[{"name":"registered","type":"bool"},{"name":"algorithm","type":"uint8"},{"name":"publicKey","type":"bytes"},{"name":"proven","type":"bool"}]}]`
const pqcStatusAddress = "0x0000000000000000000000000000000000000a02"

type EVM struct {
	client *ethclient.Client
	native *Native
	abi    abi.ABI
}

func Connect(ctx context.Context, native *Native) (*EVM, error) {
	conn, err := rpc.DialOptions(ctx, EVMRPC, rpc.WithHTTPClient(native.http))
	if err != nil {
		return nil, err
	}
	client := ethclient.NewClient(conn)
	id, err := client.ChainID(ctx)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("read Diana EVM chain ID: %w", err)
	}
	if id.Cmp(big.NewInt(EVMID)) != 0 {
		client.Close()
		return nil, errors.New("Diana EVM chain ID does not match")
	}
	contractABI, err := abi.JSON(strings.NewReader(registryABI))
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("read registry ABI: %w", err)
	}
	return &EVM{client: client, native: native, abi: contractABI}, nil
}

func (e *EVM) Close() { e.client.Close() }

type evmBlock struct {
	Hash   common.Hash    `json:"hash"`
	Number hexutil.Uint64 `json:"number"`
	Time   hexutil.Uint64 `json:"timestamp"`
}

func (e *EVM) block(ctx context.Context, height string) (evmBlock, error) {
	var block evmBlock
	if err := e.client.Client().CallContext(ctx, &block, "eth_getBlockByNumber", height, false); err != nil {
		return evmBlock{}, err
	}
	if block.Hash == (common.Hash{}) || block.Number == 0 || block.Time == 0 {
		return evmBlock{}, errors.New("Diana returned an incomplete EVM block")
	}
	return block, nil
}

func (e *EVM) finalized(ctx context.Context) (evmBlock, error) {
	block, err := e.block(ctx, "finalized")
	if err != nil {
		return evmBlock{}, fmt.Errorf("read Diana finalized EVM block: %w", err)
	}
	age := time.Since(time.Unix(int64(block.Time), 0))
	if age < -5*time.Second || age > 30*time.Second {
		return evmBlock{}, errors.New("Diana finalized EVM block is stale")
	}
	head, err := e.native.Head(ctx)
	if err != nil {
		return evmBlock{}, err
	}
	height := uint64(block.Number)
	if (height > head && height-head > 15) || (height < head && head-height > 15) {
		return evmBlock{}, errors.New("Diana native and EVM observations disagree")
	}
	return block, nil
}

func (e *EVM) codeHash(ctx context.Context, address common.Address, block common.Hash) (common.Hash, error) {
	code, err := e.client.CodeAtHash(ctx, address, block)
	if err != nil {
		return common.Hash{}, fmt.Errorf("read registry code: %w", err)
	}
	if len(code) == 0 {
		return common.Hash{}, errors.New("registry has no code at the finalized block")
	}
	return crypto.Keccak256Hash(code), nil
}

func (e *EVM) Binding(ctx context.Context, account qoresign.AccountAddress, key []byte, block common.Hash) error {
	if len(key) != qoresign.MLDSA87PublicKeyLength {
		return errors.New("invalid native signing key")
	}
	method, err := abi.JSON(strings.NewReader(pqcStatusABI))
	if err != nil {
		return err
	}
	to := common.HexToAddress(pqcStatusAddress)
	data, err := method.Pack("pqcKeyStatus", common.BytesToAddress(account.Bytes))
	if err != nil {
		return err
	}
	answer, err := e.client.CallContractAtHash(ctx, ethereum.CallMsg{To: &to, Data: data}, block)
	if err != nil {
		return fmt.Errorf("check Diana EVM account binding: %w", err)
	}
	var status struct {
		Registered bool
		Algorithm  uint8
		PublicKey  []byte
		Proven     bool
	}
	values, err := method.Unpack("pqcKeyStatus", answer)
	if err != nil {
		return err
	}
	if err := method.Methods["pqcKeyStatus"].Outputs.Copy(&status, values); err != nil {
		return err
	}
	if !status.Registered || !status.Proven || status.Algorithm != qoresign.AlgorithmMLDSA87 ||
		!bytes.Equal(status.PublicKey, key) {
		return fmt.Errorf("%w: native and EVM signing keys differ", ErrIdentityBinding)
	}
	return nil
}

func (e *EVM) Deploy(ctx context.Context, keys *identity.Keys, bytecode []byte, report func(string)) (common.Address, common.Hash, error) {
	if len(bytecode) == 0 {
		return common.Address{}, common.Hash{}, errors.New("registry bytecode is empty")
	}
	receipt, err := e.send(ctx, keys, nil, bytecode, 1800000, report)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}
	block, err := e.finalized(ctx)
	if err != nil {
		return common.Address{}, common.Hash{}, err
	}
	hash, err := e.codeHash(ctx, receipt.ContractAddress, block.Hash)
	return receipt.ContractAddress, hash, err
}

func (e *EVM) send(ctx context.Context, keys *identity.Keys, to *common.Address, data []byte, gas uint64, report func(string)) (*types.Receipt, error) {
	block, err := e.finalized(ctx)
	if err != nil {
		return nil, err
	}
	if err := e.Binding(ctx, keys.Account, keys.Signing.PublicKey, block.Hash); err != nil {
		return nil, err
	}
	gasPrice, err := e.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("read Diana gas price: %w", err)
	}
	if gasPrice.Sign() <= 0 || gasPrice.Cmp(big.NewInt(10_000_000_000_000)) > 0 {
		return nil, errors.New("Diana EVM gas price exceeds the testnet fee bound")
	}
	feeWei := new(big.Int).Mul(gasPrice, new(big.Int).SetUint64(gas))
	weiPerUqor := big.NewInt(1_000_000_000_000)
	feeUqor := new(big.Int).Add(feeWei, new(big.Int).Sub(weiPerUqor, big.NewInt(1)))
	feeUqor.Quo(feeUqor, weiPerUqor)
	if feeUqor.Cmp(big.NewInt(2_000_000)) > 0 {
		return nil, errors.New("Diana EVM transaction would use more than 2 test QOR in fees")
	}
	if err := e.openWindow(ctx, keys, to, feeUqor.String(), report); err != nil {
		return nil, err
	}
	from := common.BytesToAddress(keys.Account.Bytes)
	nonce, err := e.client.PendingNonceAt(ctx, from)
	if err != nil {
		return nil, fmt.Errorf("read Diana EVM nonce: %w", err)
	}
	account, err := e.native.account(ctx, keys)
	if err != nil {
		return nil, err
	}
	if nonce != *account.Sequence {
		return nil, errors.New("Diana native sequence and pending EVM nonce disagree")
	}
	key, err := crypto.ToECDSA(keys.Classical.PrivateKey)
	if err != nil {
		return nil, err
	}
	defer key.D.SetInt64(0)
	if crypto.PubkeyToAddress(key.PublicKey) != from {
		return nil, errors.New("EVM signer does not match the native identity")
	}
	tx := types.NewTx(&types.LegacyTx{Nonce: nonce, Gas: gas, GasPrice: gasPrice, To: to, Data: data})
	tx, err = types.SignTx(tx, types.LatestSignerForChainID(big.NewInt(EVMID)), key)
	if err != nil {
		return nil, err
	}
	if err := e.client.SendTransaction(ctx, tx); err != nil {
		return nil, fmt.Errorf("Diana EVM submission uncertain for %s: %w", tx.Hash(), err)
	}
	report("EVM transaction submitted " + tx.Hash().Hex())
	return e.waitReceipt(ctx, tx.Hash())
}

func (e *EVM) openWindow(ctx context.Context, keys *identity.Keys, to *common.Address, fee string, report func(string)) error {
	// MsgOpenEVMWindow from the Diana v3.2.9 SDK schema. Deployment needs no target
	// and receives one transaction slot. Registry calls are also target-scoped.
	account := keys.Account.Bech32
	body := qoresign.Concat(qoresign.StringField(1, account), qoresign.VarintField(2, 100),
		qoresign.VarintField(3, 1), qoresign.StringField(4, fee))
	var target string
	if to != nil {
		target = strings.ToLower(to.Hex())
		body = append(body, qoresign.StringField(6, target)...)
	}
	hash, err := e.native.Submit(ctx, keys, []qoresign.Any{{
		TypeURL: "/qorechain.pqc.v1.MsgOpenEVMWindow", Value: body,
	}})
	if err != nil {
		return fmt.Errorf("open EVM window: %w", err)
	}
	var state struct {
		Found          bool     `json:"found"`
		Live           bool     `json:"live"`
		RemainingTxs   uint64   `json:"remaining_txs,string"`
		RemainingValue string   `json:"remaining_value"`
		AllowedTargets []string `json:"allowed_targets"`
		Account        string   `json:"account"`
	}
	if err := e.native.get(ctx, REST+"/qorechain/pqc/v1/evm_window/"+account, &state); err != nil {
		return err
	}
	if !state.Found || !state.Live || state.RemainingTxs != 1 || state.RemainingValue != fee ||
		(state.Account != "" && state.Account != account) ||
		(to == nil && len(state.AllowedTargets) != 0) ||
		(to != nil && (len(state.AllowedTargets) != 1 || !strings.EqualFold(state.AllowedTargets[0], target))) {
		return errors.New("Diana EVM window does not match the requested limits")
	}
	report("EVM window confirmed " + hash)
	return nil
}

func (e *EVM) waitReceipt(ctx context.Context, hash common.Hash) (*types.Receipt, error) {
	wait, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		receipt, err := e.client.TransactionReceipt(wait, hash)
		if err == nil {
			final, err := e.finalized(wait)
			if err != nil {
				return nil, err
			}
			if receipt.TxHash == hash && receipt.BlockNumber != nil && receipt.BlockNumber.IsUint64() && uint64(final.Number) >= receipt.BlockNumber.Uint64() {
				block, err := e.block(wait, hexutil.EncodeBig(receipt.BlockNumber))
				if err != nil {
					return nil, err
				}
				if block.Hash != receipt.BlockHash {
					return nil, fmt.Errorf("Diana transaction %s has a mismatched block", hash)
				}
				if receipt.Status != types.ReceiptStatusSuccessful {
					return nil, fmt.Errorf("Diana EVM transaction %s reverted", hash)
				}
				return receipt, nil
			}
		} else if !errors.Is(err, ethereum.NotFound) {
			return nil, fmt.Errorf("Diana receipt unavailable for %s: %w", hash, err)
		}
		select {
		case <-timer.C:
		case <-wait.Done():
			return nil, fmt.Errorf("Diana EVM confirmation pending for %s: %w", hash, wait.Err())
		}
	}
}
