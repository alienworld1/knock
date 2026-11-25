package admission

import (
	"crypto/sha256"

	"knock/internal/chain"
	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
)

func seal(value any, id common.Hash, purpose string, recipients ...qoreseal.SealRecipient) ([]byte, error) {
	data, err := protocol.Encode(value)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if len(recipients) == 0 || len(recipients) > 8 ||
		qoreseal.EnvelopeSize(qoreseal.ModeHybrid, len(recipients), len(data)) > protocol.MaxEnvelope {
		return nil, ErrInvalid
	}
	return qoreseal.Seal(qoreseal.SealArgs{
		ChainID: chain.NativeID, Purpose: purpose, Recipients: recipients, Mode: qoreseal.ModeHybrid,
		Anonymous: true, Plaintext: data, AAD: id[:],
	})
}

func open(data []byte, id common.Hash, purpose string, keys qoreseal.SealKeyPair, maximum int, value any) error {
	if len(data) > protocol.MaxEnvelope {
		return ErrInvalid
	}
	envelope, err := qoreseal.ParseEnvelope(data)
	if err != nil || envelope.Mode != qoreseal.ModeHybrid || !envelope.Anonymous || len(envelope.Entries) > maximum {
		return ErrInvalid
	}
	raw, err := qoreseal.Open(qoreseal.OpenArgs{
		Envelope: data, Keys: keys, ChainID: chain.NativeID, Purpose: purpose, AAD: id[:],
	})
	if err != nil {
		return ErrInvalid
	}
	defer clear(raw)
	if err := protocol.Decode(raw, value); err != nil {
		return ErrInvalid
	}
	return nil
}

func checkedDigest(data []byte, expected common.Hash) bool {
	return sha256.Sum256(data) == expected
}
