package protocol

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"net"
	"net/url"
	"strings"

	"knock/internal/chain"
	"knock/internal/identity"

	"github.com/ethereum/go-ethereum/common"
	"github.com/fxamacker/cbor/v2"
	qoresign "github.com/qorechain/qoresign/go"
)

const MaxEnvelope = 128 << 10

var enc, _ = cbor.CoreDetEncOptions().EncMode()
var dec, _ = (cbor.DecOptions{
	DupMapKey: cbor.DupMapKeyEnforcedAPF, IndefLength: cbor.IndefLengthForbidden,
	TagsMd: cbor.TagsForbidden, MaxNestedLevels: 12, MaxMapPairs: 32,
	MaxArrayElements: 32, ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
}).DecMode()

func Encode(value any) ([]byte, error) { return enc.Marshal(value) }

func Decode(data []byte, value any) error {
	if len(data) == 0 || len(data) > MaxEnvelope || dec.Unmarshal(data, value) != nil {
		return errors.New("invalid protocol record")
	}
	canonical, err := Encode(value)
	if err != nil || !bytes.Equal(data, canonical) {
		return errors.New("noncanonical protocol record")
	}
	return nil
}

func Digest(value any) (common.Hash, error) {
	raw, err := Encode(value)
	if err != nil {
		return common.Hash{}, err
	}
	return sha256.Sum256(raw), nil
}

func signBytes(purpose string, value any) ([]byte, error) {
	return Encode(struct {
		Purpose string
		Record  any
	}{purpose, value})
}

func Sign(keys *identity.Keys, purpose string, value any) (qoresign.MessageSignature, error) {
	raw, err := signBytes(purpose, value)
	if err != nil {
		return qoresign.MessageSignature{}, err
	}
	return qoresign.SignMessage(qoresign.SignMessageArgs{
		ChainID: chain.NativeID, Signer: keys.Account.Bech32, Data: raw,
		ClassicalKey: keys.Classical, PqKey: &keys.Signing, Hedged: true,
	})
}

func Verify(account string, key []byte, purpose string, value any, signature qoresign.MessageSignature) error {
	raw, err := signBytes(purpose, value)
	if err != nil {
		return err
	}
	if len(key) != qoresign.MLDSA87PublicKeyLength || signature.Classical.KeyType != qoresign.EthSecp256k1 ||
		qoresign.VerifyMessage(qoresign.VerifyMessageOptions{
			ChainID: chain.NativeID, Signer: account, Data: raw, PqPublicKey: key, Signature: signature,
		}) != nil {
		return errors.New("couldn't verify the registered signature")
	}
	return nil
}

// Origin accepts HTTPS or an explicit IP loopback for local use.
func Origin(value string) (string, error) {
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.Path != "" || strings.Contains(u.Host, "%") ||
		(u.Scheme != "https" && (u.Scheme != "http" || !net.ParseIP(u.Hostname()).IsLoopback())) ||
		u.Scheme+"://"+u.Host != value {
		return "", errors.New("set a Mailbox HTTPS origin or an HTTP loopback IP and port")
	}
	return value, nil
}
