package lease

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"net/netip"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	ServerIP = "198.19.0.1"
	ClientIP = "198.19.0.2"
	SSHPort  = 2222
	User     = "knockssh"
)

type Connection struct {
	Endpoint    string
	ServerKey   [32]byte
	PSK         [32]byte
	HostKey     []byte
	Certificate []byte
}

func ValidateEndpoint(value string) (netip.AddrPort, error) {
	endpoint, err := netip.ParseAddrPort(value)
	if err != nil || endpoint.String() != value || endpoint.Addr().Zone() != "" ||
		!endpoint.Addr().IsGlobalUnicast() || endpoint.Port() < 1024 ||
		endpoint.Addr() == netip.MustParseAddr(ServerIP) || endpoint.Addr() == netip.MustParseAddr(ClientIP) {
		return netip.AddrPort{}, errors.New("set a WireGuard endpoint with a numeric address and UDP port above 1023")
	}
	return endpoint, nil
}

type Grant struct {
	ID        string
	Role      string
	Deadline  time.Time
	WireGuard [32]byte
	SSH       [32]byte
	Recheck   func(context.Context) error
}

func validID(id string) bool {
	decoded, err := hex.DecodeString(id)
	return len(id) == 64 && len(decoded) == 32 && err == nil && hex.EncodeToString(decoded) == id
}

func principal(id string) string { return "knock-" + id }

func (c Connection) Validate(g Grant) error {
	if _, err := ValidateEndpoint(c.Endpoint); err != nil {
		return err
	}
	host, err := ssh.ParsePublicKey(c.HostKey)
	if err != nil || host.Type() != ssh.KeyAlgoED25519 || c.ServerKey == ([32]byte{}) || c.PSK == ([32]byte{}) {
		return errors.New("invalid Door connection keys")
	}
	pub, err := ssh.ParsePublicKey(c.Certificate)
	if err != nil {
		return errors.New("invalid SSH certificate")
	}
	cert, ok := pub.(*ssh.Certificate)
	key, keyErr := ssh.NewPublicKey(ed25519.PublicKey(g.SSH[:]))
	if !ok || keyErr != nil || cert.CertType != ssh.UserCert || cert.KeyId != principal(g.ID) ||
		len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != principal(g.ID) ||
		string(cert.Key.Marshal()) != string(key.Marshal()) || cert.ValidBefore != uint64(g.Deadline.Unix()) ||
		cert.ValidAfter >= cert.ValidBefore || cert.CriticalOptions["source-address"] != ClientIP+"/32" {
		return errors.New("SSH certificate differs from the approved session")
	}
	return nil
}

type State string

const (
	Reserved          State = "Reserved"
	Provisioning      State = "Provisioning"
	Ready             State = "Ready"
	Active            State = "Active"
	Closing           State = "Closing"
	Closed            State = "Closed"
	CleanupIncomplete State = "Cleanup incomplete"
)
