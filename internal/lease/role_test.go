package lease

import (
	"bytes"
	"strings"
	"testing"
)

func TestRoleMenuAndEnforcement(t *testing.T) {
	id := strings.Repeat("a", 64)
	var out bytes.Buffer
	in := strings.NewReader("\n   \nhelp\nstatus\nstart\nunknown\nquit\n")
	if err := Role("logs", id, "", in, &out); err != nil {
		t.Fatalf("logs interactive role failed: %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"Knock SSH session (role: logs)",
		"Commands: status, help, quit",
		"status  show host uptime",
		"Host uptime:",
		"command unavailable for this role",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in logs output:\n%s", want, text)
		}
	}
	if strings.Contains(text, "start   start one") {
		t.Fatalf("logs help advertised maintenance start command:\n%s", text)
	}

	out.Reset()
	if err := Role("maintenance", id, "help", strings.NewReader(""), &out); err != nil {
		t.Fatalf("maintenance help command failed: %v", err)
	}
	if !strings.Contains(out.String(), "start   start one contained diagnostic workload") {
		t.Fatalf("maintenance help omitted start:\n%s", out.String())
	}

	if err := Role("admin", id, "status", strings.NewReader(""), &out); err == nil {
		t.Fatal("accepted unsupported role")
	}
	if err := Role("logs", "not-hex", "status", strings.NewReader(""), &out); err == nil {
		t.Fatal("accepted invalid session ID")
	}
}
