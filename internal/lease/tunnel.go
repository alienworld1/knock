package lease

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// Tunnel accepts keys on stdin and limits privileged changes to an owned link
// and one approved private route in the requester's own Linux VM.
func Tunnel(ctx context.Context, action, name string, in io.Reader) error {
	uid, err := strconv.ParseUint(os.Getenv("SUDO_UID"), 10, 32)
	if err != nil || uid == 0 || os.Getuid() != 0 || len(name) != 14 || !strings.HasPrefix(name, "kc") {
		return errors.New("invalid Knock tunnel permissions or interface name")
	}
	raw, err := hex.DecodeString(name[2:])
	if err != nil || hex.EncodeToString(raw) != name[2:] {
		return errors.New("invalid Knock tunnel interface name")
	}
	call, cancel := context.WithTimeout(ctx, 9*time.Second)
	defer cancel()
	alias := "Knock requester " + strconv.FormatUint(uid, 10)
	switch action {
	case "up":
		var spec tunnelSpec
		defer clear(spec.PrivateKey[:])
		defer clear(spec.PSK[:])
		dec := json.NewDecoder(io.LimitReader(in, 4096))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&spec); err != nil || dec.Decode(new(json.RawMessage)) != io.EOF ||
			spec.PrivateKey == ([32]byte{}) || spec.PSK == ([32]byte{}) || spec.Peer == ([32]byte{}) {
			return errors.New("invalid Knock tunnel configuration")
		}
		if _, err := ValidateEndpoint(spec.Endpoint); err != nil {
			return err
		}
		if err := run(call, ipPath, "link", "add", "name", name, "type", "wireguard"); err != nil {
			return err
		}
		if err := configureLink(call, name, alias, spec); err != nil {
			cleanup, stop := context.WithTimeout(context.Background(), 4*time.Second)
			defer stop()
			return errors.Join(err, run(cleanup, ipPath, "link", "delete", "dev", name))
		}
		return nil
	case "down":
		out, err := native(call, nil, ipPath, "-j", "link", "show")
		if err != nil {
			return err
		}
		var links []struct {
			Name  string `json:"ifname"`
			Alias string `json:"ifalias"`
		}
		if err := json.Unmarshal(out, &links); err != nil {
			return err
		}
		for _, link := range links {
			if link.Name == name {
				if link.Alias != alias {
					return errors.New("the link is not owned by this Knock user")
				}
				return run(call, ipPath, "link", "delete", "dev", name)
			}
		}
		return nil
	default:
		return errors.New("invalid Knock tunnel action")
	}
}

func configureLink(ctx context.Context, name, alias string, spec tunnelSpec) error {
	defer clear(spec.PrivateKey[:])
	defer clear(spec.PSK[:])
	if err := run(ctx, ipPath, "link", "set", "dev", name, "alias", alias); err != nil {
		return err
	}
	if err := run(ctx, ipPath, "address", "add", ClientIP+"/32", "dev", name); err != nil {
		return err
	}
	if err := setWG(ctx, spec.PrivateKey[:], name, "private-key", "/dev/stdin"); err != nil {
		return err
	}
	if err := setWG(ctx, spec.PSK[:], name, "peer", wgText(spec.Peer[:]), "preshared-key", "/dev/stdin",
		"allowed-ips", ServerIP+"/32", "endpoint", spec.Endpoint); err != nil {
		return err
	}
	if err := run(ctx, ipPath, "link", "set", "dev", name, "up"); err != nil {
		return err
	}
	return run(ctx, ipPath, "route", "add", ServerIP+"/32", "dev", name, "src", ClientIP)
}
