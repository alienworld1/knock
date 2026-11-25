package lease

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const device = "knockdoor"
const table = "knock_ssh"

const firewall = `table inet knock_ssh {
	set lease_in { type ipv4_addr . ipv4_addr . inet_service; flags timeout; }
	set lease_out { type ipv4_addr . ipv4_addr . inet_service; flags timeout; }
	chain inbound {
		type filter hook input priority -20; policy accept;
		iifname "knockdoor" ip saddr . ip daddr . tcp dport @lease_in accept
		iifname "knockdoor" drop
		tcp dport 2222 ip daddr 198.19.0.1 drop
	}
	chain outbound {
		type filter hook output priority -20; policy accept;
		oifname "knockdoor" ip saddr . ip daddr . tcp sport @lease_out accept
		oifname "knockdoor" drop
		tcp sport 2222 ip saddr 198.19.0.1 drop
	}
	chain routed {
		type filter hook forward priority -20; policy accept;
		iifname "knockdoor" drop
		oifname "knockdoor" drop
	}
}
`

func nft(ctx context.Context, commands string) error {
	_, err := native(ctx, []byte(commands), nftPath, "-f", "-")
	return err
}

func enable(ctx context.Context, deadline time.Time) error {
	ms := time.Until(deadline).Milliseconds()
	if ms <= 0 {
		return errors.New("the session deadline passed during provisioning")
	}
	return nft(ctx, fmt.Sprintf("add element inet %s lease_in { %s . %s . %d timeout %dms }\nadd element inet %s lease_out { %s . %s . %d timeout %dms }\n",
		table, ClientIP, ServerIP, SSHPort, ms, table, ServerIP, ClientIP, SSHPort, ms))
}

func deny(ctx context.Context) error {
	return nft(ctx, "flush set inet "+table+" lease_in\nflush set inet "+table+" lease_out\n")
}

func denyVerified(ctx context.Context) error {
	for _, name := range []string{"lease_in", "lease_out"} {
		data, err := native(ctx, nil, nftPath, "-j", "list", "set", "inet", table, name)
		if err != nil {
			return err
		}
		var output struct {
			Objects []struct {
				Set *struct {
					Name     string            `json:"name"`
					Elements []json.RawMessage `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(data, &output); err != nil {
			return err
		}
		verified := false
		for _, item := range output.Objects {
			if item.Set != nil && item.Set.Name == name && len(item.Set.Elements) == 0 {
				verified = true
			}
		}
		if !verified {
			return errors.New("a Knock network permit remains or could not be verified")
		}
	}
	return nil
}
