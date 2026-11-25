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

var firewall = fmt.Sprintf(`table inet knock_ssh {
	set lease_in { type ipv4_addr . ipv4_addr . inet_service; flags timeout; }
	set lease_out { type ipv4_addr . ipv4_addr . inet_service; flags timeout; }
	chain inbound {
		type filter hook input priority -20; policy accept;
		iifname "knockdoor" ip saddr . ip daddr . tcp dport @lease_in accept
		iifname "knockdoor" drop
		tcp dport %d-%d ip daddr %s drop
	}
	chain outbound {
		type filter hook output priority -20; policy accept;
		oifname "knockdoor" ip saddr . ip daddr . tcp sport @lease_out accept
		oifname "knockdoor" drop
		tcp sport %d-%d ip saddr %s drop
	}
	chain routed {
		type filter hook forward priority -20; policy accept;
		iifname "knockdoor" drop
		oifname "knockdoor" drop
	}
}
`, SSHPort, SSHPort+slotCount-1, ServerIP, SSHPort, SSHPort+slotCount-1, ServerIP)

func nft(ctx context.Context, commands string) error {
	_, err := native(ctx, []byte(commands), nftPath, "-f", "-")
	return err
}

type permit struct {
	set, source, destination string
	port                     int
}

func permits(assigned slot) [2]permit {
	return [2]permit{
		{"lease_in", assigned.clientIP(), ServerIP, assigned.port()},
		{"lease_out", ServerIP, assigned.clientIP(), assigned.port()},
	}
}

func (p permit) tuple() string {
	return fmt.Sprintf("%s . %s . %d", p.source, p.destination, p.port)
}

func enable(ctx context.Context, assigned slot, deadline time.Time) error {
	ms := time.Until(deadline).Milliseconds()
	if ms <= 0 {
		return errors.New("the session deadline passed during provisioning")
	}
	var commands string
	for _, p := range permits(assigned) {
		commands += fmt.Sprintf("add element inet %s %s { %s timeout %dms }\n", table, p.set, p.tuple(), ms)
	}
	return nft(ctx, commands)
}

func deny(ctx context.Context, assigned slot) error {
	var result error
	for _, p := range permits(assigned) {
		remove := nft(ctx, fmt.Sprintf("delete element inet %s %s { %s }\n", table, p.set, p.tuple()))
		if err := p.verifyAbsent(ctx); err != nil {
			result = errors.Join(result, remove, err)
		}
	}
	return result
}

func (p permit) verifyAbsent(ctx context.Context) error {
	data, err := native(ctx, nil, nftPath, "-j", "list", "set", "inet", table, p.set)
	if err != nil {
		return err
	}
	return p.absent(data)
}

func (p permit) absent(data []byte) error {
	type tuple struct {
		Concat []json.RawMessage `json:"concat"`
	}
	var output struct {
		Objects []struct {
			Set *struct {
				Name, Table, Family string
				Elements            []struct {
					tuple
					Element *struct {
						Value tuple `json:"val"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(data, &output); err != nil {
		return err
	}
	for _, item := range output.Objects {
		if item.Set == nil || item.Set.Name != p.set || item.Set.Table != table || item.Set.Family != "inet" {
			continue
		}
		for _, element := range item.Set.Elements {
			value := element.tuple
			if element.Element != nil {
				value = element.Element.Value
			}
			var src, dst string
			var port int
			if len(value.Concat) != 3 || json.Unmarshal(value.Concat[0], &src) != nil ||
				json.Unmarshal(value.Concat[1], &dst) != nil || json.Unmarshal(value.Concat[2], &port) != nil {
				return errors.New("couldn't verify a Knock network permit")
			}
			if src == p.source && dst == p.destination && port == p.port {
				return errors.New("a Knock network permit remains")
			}
		}
		return nil
	}
	return errors.New("couldn't verify the Knock permit set")
}
