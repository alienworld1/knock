package command

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestStyleHelpersAvoidANSIWithoutTTY(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	var buf bytes.Buffer
	OK(&buf, "Door identity verified")
	Wait(&buf, "Waiting for approval…")
	Warn(&buf, "Session updates unavailable.")
	Fail(&buf, "Request expired")
	Field(&buf, "Door", "qor1test")

	out := buf.String()
	if strings.Contains(out, "\x1b") {
		t.Fatalf("emitted ANSI escape codes to non-TTY buffer: %q", out)
	}
	for _, want := range []string{
		"[ok] Door identity verified",
		"[wait] Waiting for approval…",
		"[warn] Session updates unavailable.",
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

func TestDurationFormatting(t *testing.T) {
	cases := []struct {
		in   time.Duration
		want string
	}{
		{-5 * time.Second, "0s"},
		{0, "0s"},
		{45 * time.Second, "45s"},
		{5 * time.Minute, "5m"},
		{90 * time.Second, "1m 30s"},
		{time.Hour, "1h"},
		{3661 * time.Second, "1h 1m 1s"},
	}
	for _, tc := range cases {
		if got := Duration(tc.in); got != tc.want {
			t.Fatalf("Duration(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
	if got := UTC(0); got != "1970-01-01 00:00:00 UTC" {
		t.Fatalf("UTC(0) = %q", got)
	}
}
