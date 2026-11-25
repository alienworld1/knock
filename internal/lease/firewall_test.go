package lease

import (
	"fmt"
	"testing"
)

func TestPermitVerificationKeepsOtherSlotsIndependent(t *testing.T) {
	other := permits(1)[0]
	remaining := fmt.Sprintf(`{"nftables":[{"set":{"family":"inet","table":"knock_ssh","name":"lease_in","elem":[{"elem":{"val":{"concat":["%s","%s",%d]},"timeout":30000,"expires":22200}}]}}]}`,
		other.source, other.destination, other.port)
	if err := permits(0)[0].absent([]byte(remaining)); err != nil {
		t.Fatalf("unrelated permit affected closure: %v", err)
	}
	if err := other.absent([]byte(remaining)); err == nil {
		t.Fatal("reported an extant permit absent")
	}
	for _, unknown := range []string{`{"nftables":[]}`, `{"nftables":[{"set":{"family":"inet","table":"knock_ssh","name":"lease_in","elem":[{}]}}]}`} {
		if err := other.absent([]byte(unknown)); err == nil {
			t.Fatal("reported absent permit without readable verification evidence")
		}
	}
}

func TestSlotAddressesAndAccountsAreUnique(t *testing.T) {
	addresses, ports, accounts := map[string]bool{}, map[int]bool{}, map[string]bool{}
	for assigned := slot(0); assigned.valid(); assigned++ {
		addr, port, user := assigned.clientIP(), assigned.port(), assigned.user()
		if addresses[addr] || ports[port] || accounts[user] {
			t.Fatal("SSH slots share a client address, port or account")
		}
		addresses[addr], ports[port], accounts[user] = true, true, true
	}
}
