package mailbox

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"time"

	"knock/internal/protocol"

	"github.com/ethereum/go-ethereum/common"
	qoresign "github.com/qorechain/qoresign/go"
)

const (
	authPurpose = "knock-mailbox-auth-v1"
	Retention   = 15 * time.Minute
	PageSize    = 16
	MaxInbox    = 64
	maxJSON     = (protocol.MaxEnvelope*4/3 + 2048) * PageSize
)

type Challenge struct {
	Version uint64      `json:"version"`
	Origin  string      `json:"origin"`
	Account string      `json:"account"`
	Nonce   common.Hash `json:"nonce"`
	Expires int64       `json:"expires"`
}

type proof struct {
	Challenge Challenge                 `json:"challenge"`
	Signature qoresign.MessageSignature `json:"signature"`
}

type session struct {
	Token   string `json:"token"`
	Expires int64  `json:"expires"`
}

type Message struct {
	Route   string      `json:"route"`
	ID      common.Hash `json:"id"`
	Expires int64       `json:"expires"`
	Body    ciphertext  `json:"ciphertext"`
}

type page struct {
	Messages []Message    `json:"messages"`
	Next     *common.Hash `json:"next,omitempty"`
}

func decode(r io.Reader, dst any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil || dec.Decode(new(json.RawMessage)) != io.EOF {
		return errors.New("invalid Mailbox response or input")
	}
	return nil
}

type ciphertext []byte

func (b ciphertext) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.RawURLEncoding.EncodeToString(b))
}

func (b *ciphertext) UnmarshalJSON(data []byte) error {
	var encoded string
	if err := json.Unmarshal(data, &encoded); err != nil || len(encoded) > base64.RawURLEncoding.EncodedLen(protocol.MaxEnvelope) {
		return errors.New("invalid Mailbox ciphertext")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(raw) != encoded {
		return errors.New("invalid Mailbox ciphertext")
	}
	*b = raw
	return nil
}
