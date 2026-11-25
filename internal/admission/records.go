package admission

import (
	"crypto/sha256"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"knock/internal/door"
	"knock/internal/lease"
	"knock/internal/mailbox"

	"github.com/ethereum/go-ethereum/common"
	qoreseal "github.com/qorechain/qoreseal/go"
	qoresign "github.com/qorechain/qoresign/go"
)

const (
	RequestLifetime = 5 * time.Minute
	MaxReason       = 512

	doorInner         = "knock-door-intent-v1"
	reviewInner       = "knock-approval-intent-v1"
	doorDelivery      = "knock-door-delivery-v1"
	reviewDelivery    = "knock-approval-delivery-v1"
	manifestPurpose   = "knock-request-manifest-v1"
	decisionPurpose   = "knock-entry-pass-v1"
	statusPurpose     = "knock-admission-status-v1"
	connectionPurpose = "knock-ssh-connection-v1"
)

var (
	ErrInvalid = errors.New("couldn't verify the admission record")
	ErrExpired = errors.New("Request expired")
	ErrPending = errors.New("request delivery is pending")
	ErrPolicy  = errors.New("Door policy changed or access is disabled")
)

type Binding struct {
	Account string
	Signing common.Hash
	KEM     common.Hash
	X25519  common.Hash
}

func binding(account string, key []byte, recipient qoreseal.SealRecipient) Binding {
	return Binding{account, sha256.Sum256(key), sha256.Sum256(recipient.MlkemPublicKey), sha256.Sum256(recipient.X25519PublicKey)}
}

type authorization struct {
	Version    uint64
	Native     string
	EVM        uint64
	Registry   common.Address
	DoorID     common.Hash
	RequestID  common.Hash
	Door       Binding
	Requester  Binding
	Policy     uint64
	PolicyHash common.Hash
	Service    string
	Role       string
	Seconds    uint64
	Created    int64
	Deadline   int64
	Salt       common.Hash
}

type doorPayload struct {
	Authorization authorization
	WireGuard     [32]byte
	SSH           [32]byte
	Reply         qoreseal.SealRecipient
	ReplyRoute    string
}

type approvalPayload struct {
	Authorization authorization
	DoorEnvelope  common.Hash
	Reason        string
	ReviewSalt    common.Hash
}

type manifest struct {
	Authorization  common.Hash
	RequestID      common.Hash
	Door           Binding
	DoorID         common.Hash
	Requester      Binding
	RequesterCard  qoreseal.RecipientCard
	Approvers      []Binding
	DoorEnvelope   common.Hash
	ReviewEnvelope common.Hash
	Deadline       int64
	Mode           string
}

type signedManifest struct {
	Record    manifest
	Signature qoresign.MessageSignature
}

type delivery struct {
	Manifest signedManifest
	Inner    []byte
}

type decision struct {
	Authorization authorization
	Manifest      common.Hash
	DoorEnvelope  common.Hash
	Reviewed      common.Hash
	Approver      Binding
	ApproverCard  qoreseal.RecipientCard
	Outcome       Outcome
	Issued        int64
	Deadline      int64
}

type signedDecision struct {
	Record    decision
	Signature qoresign.MessageSignature
}

type Outcome string

const (
	Pending         Outcome = "Requested"
	Authorized      Outcome = "Authorized"
	Denied          Outcome = "Denied"
	Expired         Outcome = "Request expired"
	Ready           Outcome = "Ready"
	ProvisionFailed Outcome = "Provisioning failed"
)

type status struct {
	Authorization common.Hash
	Manifest      common.Hash
	Decision      common.Hash
	RequestID     common.Hash
	Session       common.Hash
	Door          Binding
	Reply         common.Hash
	Outcome       Outcome
	Issued        int64
	Deadline      int64
	Connection    *connection `cbor:",omitempty"`
}

type connection struct {
	Issued          int64
	Deadline        int64
	ClientWireGuard [32]byte
	Data            lease.Connection
}

func connectionID(session common.Hash) common.Hash {
	return recordID(connectionPurpose, session, common.Hash{}, "")
}

type signedStatus struct {
	Record    status
	Signature qoresign.MessageSignature
}

func ValidReason(reason string) bool {
	if len(reason) == 0 || len(reason) > MaxReason || strings.TrimSpace(reason) == "" || !utf8.ValidString(reason) {
		return false
	}
	for _, r := range reason {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func SessionReference(doorID, requestID common.Hash) common.Hash {
	return recordID("knock-session-reference-v1", doorID, requestID, "")
}

func recordID(purpose string, doorID, requestID common.Hash, variant string) common.Hash {
	hash := sha256.New()
	hash.Write([]byte(purpose))
	hash.Write([]byte{0})
	hash.Write(doorID[:])
	hash.Write(requestID[:])
	hash.Write([]byte(variant))
	return common.Hash(hash.Sum(nil))
}

func (a authorization) valid(d door.Details, now int64) error {
	if a.Version != 1 || a.Native != d.NativeChain || a.EVM != d.EVMChain || a.Registry != d.Registry.Address ||
		a.DoorID != d.DoorID || a.Door.Account != d.Account || a.Door.Signing != d.SigningKey ||
		a.Door.KEM != d.KEMKey || a.Requester.Account == a.Door.Account || a.RequestID == (common.Hash{}) ||
		a.Salt == (common.Hash{}) || a.Service != "ssh" || a.Created > now+5 || a.Created < now-int64(mailbox.Retention/time.Second) ||
		a.Deadline != a.Created+int64(RequestLifetime/time.Second) || a.Seconds == 0 {
		return ErrInvalid
	}
	if a.Deadline <= now {
		return ErrExpired
	}
	if !d.Policy.Enabled || a.Policy != d.Policy.Version || a.PolicyHash != d.PolicyCommitment ||
		!validScope(d, a.Role, a.Seconds) {
		return ErrPolicy
	}
	return nil
}

func validScope(d door.Details, role string, seconds uint64) bool {
	if seconds == 0 || seconds > d.Policy.MaxDurationSeconds {
		return false
	}
	for _, allowed := range d.Policy.Roles {
		if role == allowed {
			return true
		}
	}
	return false
}
