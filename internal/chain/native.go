package chain

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"knock/internal/identity"

	qoreseal "github.com/qorechain/qoreseal/go"
	sealnet "github.com/qorechain/qoreseal/go/network"
	qoresign "github.com/qorechain/qoresign/go"
	signnet "github.com/qorechain/qoresign/go/network"
)

const (
	NativeID = "qorechain-diana"
	EVMID    = 9800
	REST     = "https://api-testnet.qore.host"
	RPC      = "https://rpc-testnet.qore.host"
	EVMRPC   = "https://evm-testnet.qore.host"
)

type Native struct {
	http *http.Client
	sign *signnet.Client
}

func Diana() *Native {
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	return &Native{http: client, sign: &signnet.Client{HTTP: client, REST: REST}}
}

var (
	errNotFound        = errors.New("chain record not found")
	ErrIdentityBinding = errors.New("Diana identity binding is invalid or stale")
)

func (n *Native) get(ctx context.Context, url string, output any) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	response, err := n.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return errNotFound
	}
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("Diana returned HTTP %d", response.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(output)
}

func (n *Native) Head(ctx context.Context) (uint64, error) {
	var status struct {
		Result struct {
			Node struct {
				Network string `json:"network"`
			} `json:"node_info"`
			Sync struct {
				Height     uint64    `json:"latest_block_height,string"`
				Time       time.Time `json:"latest_block_time"`
				CatchingUp bool      `json:"catching_up"`
			} `json:"sync_info"`
		} `json:"result"`
	}
	if err := n.get(ctx, RPC+"/status", &status); err != nil {
		return 0, err
	}
	sync := status.Result.Sync
	age := time.Since(sync.Time)
	if status.Result.Node.Network != NativeID || sync.Height == 0 || sync.CatchingUp || age < -5*time.Second || age > 30*time.Second {
		return 0, errors.New("Diana native head is stale or on the wrong network")
	}
	return sync.Height, nil
}

func (n *Native) SigningKey(ctx context.Context, account string) ([]byte, error) {
	record, err := n.sign.FetchPqKeyStatus(ctx, account)
	if err != nil {
		return nil, err
	}
	if !record.Registered || !record.PossessionProven || record.KeyType != "hybrid" ||
		record.AlgorithmID != qoresign.AlgorithmMLDSA87 || len(record.PublicKey) != qoresign.MLDSA87PublicKeyLength ||
		qoresign.IsDegeneratePqPublicKey(record.PublicKey) {
		return nil, fmt.Errorf("%w: account has no proven hybrid signing key", ErrIdentityBinding)
	}
	return record.PublicKey, nil
}

func (n *Native) Recipient(ctx context.Context, card qoreseal.RecipientCard, account string) (qoreseal.SealRecipient, error) {
	_, recipient, err := n.RecipientBinding(ctx, card, account)
	return recipient, err
}

func (n *Native) RecipientBinding(ctx context.Context, card qoreseal.RecipientCard, account string) ([]byte, qoreseal.SealRecipient, error) {
	height, err := n.Head(ctx)
	if err != nil {
		return nil, qoreseal.SealRecipient{}, err
	}
	issued, err := time.Parse(time.RFC3339, card.IssuedAt)
	if err != nil || issued.After(time.Now().Add(5*time.Second)) {
		return nil, qoreseal.SealRecipient{}, fmt.Errorf("%w: recipient card has an invalid issue time", ErrIdentityBinding)
	}
	public, err := n.SigningKey(ctx, account)
	if err != nil {
		return nil, qoreseal.SealRecipient{}, err
	}
	recipient, err := (&sealnet.Client{REST: REST, HTTP: n.http}).FetchKemKey(ctx, account)
	if err != nil {
		return nil, qoreseal.SealRecipient{}, err
	}
	if !recipient.Registered || recipient.Address != account || recipient.AlgorithmID != qoreseal.AlgorithmMLKEM1024 ||
		recipient.RegisteredHeight <= 0 || uint64(recipient.RegisteredHeight) > height {
		return nil, qoreseal.SealRecipient{}, fmt.Errorf("%w: account has no verified ML-KEM-1024 key at the observed Diana height", ErrIdentityBinding)
	}
	verified, err := qoreseal.VerifyRecipientCard(qoreseal.VerifyRecipientCardArgs{
		ChainID: NativeID, Address: account, Card: card, PqPublicKey: public, MlkemPublicKey: recipient.PublicKey,
	})
	if err != nil {
		return nil, verified, fmt.Errorf("%w: recipient card could not be verified", ErrIdentityBinding)
	}
	return public, verified, nil
}

func (n *Native) Register(ctx context.Context, keys *identity.Keys, report func(string)) (qoreseal.RecipientCard, error) {
	if _, err := n.Head(ctx); err != nil {
		return qoreseal.RecipientCard{}, err
	}
	account := keys.Account.Bech32
	record, err := n.sign.FetchPqKeyStatus(ctx, account)
	if err != nil {
		return qoreseal.RecipientCard{}, err
	}
	if !record.Registered {
		msg, err := qoresign.BuildRegisterPqKeyMessage(qoresign.RegisterPqKeyArgs{
			ChainID: NativeID, Account: account, PqKey: keys.Signing, ClassicalPublicKey: keys.Classical.PublicKey, Hedged: true,
		})
		if err != nil {
			return qoreseal.RecipientCard{}, err
		}
		hash, err := n.submit(ctx, keys, qoresign.ModeClassicalOnly, []qoresign.Any{msg})
		if err != nil {
			return qoreseal.RecipientCard{}, fmt.Errorf("register signing key: %w", err)
		}
		report("Signing key confirmed " + hash)
	}
	public, err := n.SigningKey(ctx, account)
	if err != nil {
		return qoreseal.RecipientCard{}, err
	}
	if !bytes.Equal(public, keys.Signing.PublicKey) {
		return qoreseal.RecipientCard{}, errors.New("local signing key differs from the registered key")
	}
	if err := n.registerKEM(ctx, keys, report); err != nil {
		return qoreseal.RecipientCard{}, err
	}
	card, err := qoreseal.SignRecipientCard(qoreseal.SignRecipientCardArgs{
		ChainID: NativeID, Address: account, Keys: keys.Recipient, ClassicalKey: keys.Classical, PqKey: keys.Signing,
	})
	if err != nil {
		return qoreseal.RecipientCard{}, err
	}
	_, err = n.Recipient(ctx, card, account)
	return card, err
}

func (n *Native) registerKEM(ctx context.Context, keys *identity.Keys, report func(string)) error {
	client := &sealnet.Client{REST: REST, HTTP: n.http}
	record, err := client.FetchKemKey(ctx, keys.Account.Bech32)
	if err != nil {
		return err
	}
	if record.Registered {
		if !bytes.Equal(record.PublicKey, keys.Recipient.MlkemPublicKey) {
			return errors.New("local recipient key differs from the registered key")
		}
		return nil
	}
	msg, err := qoreseal.BuildRegisterKemKeyMessage(keys.Account.Bech32, keys.Recipient.MlkemPublicKey)
	if err != nil {
		return err
	}
	hash, err := n.Submit(ctx, keys, []qoresign.Any{msg})
	if err != nil {
		return fmt.Errorf("register recipient key: %w", err)
	}
	report("Recipient key confirmed " + hash)
	return nil
}

type baseAccount struct {
	Address   string  `json:"address"`
	Number    *uint64 `json:"account_number,string"`
	Sequence  *uint64 `json:"sequence,string"`
	PublicKey *struct {
		Type string `json:"@type"`
		Key  []byte `json:"key"`
	} `json:"pub_key"`
}

const etherPublicKey = "/cosmos.evm.crypto.v1.ethsecp256k1.PubKey"

func (n *Native) account(ctx context.Context, keys *identity.Keys) (baseAccount, error) {
	var result struct {
		Account struct {
			baseAccount
			Base *baseAccount `json:"base_account"`
		} `json:"account"`
	}
	if err := n.get(ctx, REST+"/cosmos/auth/v1beta1/accounts/"+keys.Account.Bech32, &result); err != nil {
		return baseAccount{}, fmt.Errorf("read funded Diana account: %w", err)
	}
	account := result.Account.baseAccount
	if result.Account.Base != nil {
		account = *result.Account.Base
	}
	if account.Address != keys.Account.Bech32 || account.Number == nil || account.Sequence == nil {
		return baseAccount{}, errors.New("Diana account data is incomplete or mismatched")
	}
	if account.PublicKey != nil &&
		(account.PublicKey.Type != etherPublicKey || !bytes.Equal(account.PublicKey.Key, keys.Classical.PublicKey)) {
		return baseAccount{}, errors.New("registered classical account key does not match the EVM-capable identity")
	}
	return account, nil
}

func (n *Native) Submit(ctx context.Context, keys *identity.Keys, messages []qoresign.Any) (string, error) {
	return n.submit(ctx, keys, qoresign.ModeHybrid, messages)
}

func (n *Native) submit(ctx context.Context, keys *identity.Keys, mode qoresign.SigningMode, messages []qoresign.Any) (string, error) {
	head, err := n.Head(ctx)
	if err != nil {
		return "", err
	}
	account, err := n.account(ctx, keys)
	if err != nil {
		return "", err
	}
	body, auth := nativeTransaction(keys.Classical.PublicKey, *account.Sequence, head+100, messages)
	tx, err := qoresign.SignHybrid(qoresign.SignHybridArgs{
		ChainID: NativeID, AccountNumber: *account.Number, BodyBytes: body, AuthInfoBytes: auth, ClassicalKey: keys.Classical,
		PqKey: &keys.Signing, Mode: mode, SignBytesVersion: qoresign.SignBytesV2, Hedged: true,
	})
	if err != nil {
		return "", err
	}
	hash := fmt.Sprintf("%X", sha256.Sum256(tx.TxBytes))
	admission, err := n.sign.BroadcastTx(ctx, tx.TxBytes)
	if err != nil {
		return hash, fmt.Errorf("Diana submission uncertain for %s: %w", hash, err)
	}
	if admission.Code != 0 {
		return hash, fmt.Errorf("Diana refused %s (%s code %d)", hash, admission.Codespace, admission.Code)
	}
	if !strings.EqualFold(admission.TxHash, hash) {
		return hash, fmt.Errorf("Diana returned a mismatched transaction hash for %s", hash)
	}
	confirmation, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	return hash, n.wait(confirmation, hash)
}

func nativeTransaction(publicKey []byte, sequence, timeoutHeight uint64, messages []qoresign.Any) ([]byte, []byte) {
	var body []byte
	for _, msg := range messages {
		body = append(body, qoresign.LenField(1, qoresign.EncodeAny(msg))...)
	}
	body = append(body, qoresign.VarintField(3, timeoutHeight)...)
	public := qoresign.EncodeAny(qoresign.Any{TypeURL: etherPublicKey, Value: qoresign.LenField(1, publicKey)})
	direct := qoresign.LenField(1, qoresign.VarintField(1, 1))
	signer := qoresign.Concat(qoresign.LenField(1, public), qoresign.LenField(2, direct))
	if sequence > 0 {
		signer = append(signer, qoresign.VarintField(3, sequence)...)
	}
	coin := qoresign.Concat(qoresign.StringField(1, "uqor"), qoresign.StringField(2, "100000"))
	fee := qoresign.Concat(qoresign.LenField(1, coin), qoresign.VarintField(2, 800000))
	return body, qoresign.Concat(qoresign.LenField(1, signer), qoresign.LenField(2, fee))
}

func (n *Native) wait(ctx context.Context, hash string) error {
	timer := time.NewTicker(time.Second)
	defer timer.Stop()
	for {
		var observation struct {
			Tx struct {
				Hash      string  `json:"txhash"`
				Code      *uint32 `json:"code"`
				Height    uint64  `json:"height,string"`
				Codespace string  `json:"codespace"`
			} `json:"tx_response"`
		}
		err := n.get(ctx, REST+"/cosmos/tx/v1beta1/txs/"+hash, &observation)
		if err == nil {
			tx := observation.Tx
			if tx.Code == nil || tx.Height == 0 || !strings.EqualFold(tx.Hash, hash) {
				return fmt.Errorf("Diana returned incomplete confirmation for %s", hash)
			}
			if *tx.Code != 0 {
				return fmt.Errorf("Diana transaction %s failed (%s code %d)", hash, tx.Codespace, *tx.Code)
			}
			head, err := n.Head(ctx)
			if err != nil || head < tx.Height {
				return fmt.Errorf("Diana did not verify the committed block for %s", hash)
			}
			return nil
		}
		if !errors.Is(err, errNotFound) {
			return fmt.Errorf("confirmation unavailable for %s: %w", hash, err)
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("confirmation pending for %s: %w", hash, ctx.Err())
		case <-timer.C:
		}
	}
}
