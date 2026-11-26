package command

import (
	"bytes"
	"strings"
	"testing"
)

func TestStyleHelpersAvoidANSIWithoutTTY(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	OK(&buf, "Door identity verified")
	Wait(&buf, "Waiting for approval…")
	Fail(&buf, "Request expired")
	Field(&buf, "Door", "qor1test")

	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("emitted ANSI escape codes to non-TTY buffer: %q", out)
	}
	for _, want := range []string{
		"[ok] Door identity verified",
		"[wait] Waiting for approval…",
		"[error] Request expired",
		"Door               qor1test",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
	if ColorEnabled(&buf) || UTF8Enabled(&buf) {
		t.Fatal("reported terminal capabilities for non-file writer")
	}
}
