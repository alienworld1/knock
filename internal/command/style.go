package command

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"golang.org/x/term"
)

// ColorEnabled reports whether w is an interactive terminal that allows ANSI colors.
func ColorEnabled(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	return os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
}

// UTF8Enabled reports whether w is an interactive terminal configured for UTF-8.
func UTF8Enabled(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	for _, key := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if value := os.Getenv(key); value != "" {
			lower := strings.ToLower(value)
			return strings.Contains(lower, "utf-8") || strings.Contains(lower, "utf8")
		}
	}
	return false
}

func statusLine(w io.Writer, symbol, ascii, ansiColor, message string) {
	prefix := ascii
	if UTF8Enabled(w) {
		if ColorEnabled(w) && ansiColor != "" {
			prefix = ansiColor + symbol + "\x1b[0m"
		} else {
			prefix = symbol
		}
	}
	fmt.Fprintf(w, "%s %s\n", prefix, message)
}

// OK writes a verified completion line to w.
func OK(w io.Writer, message string) { statusLine(w, "✓", "[ok]", "\x1b[32m", message) }

// Wait writes an in-progress status line to w.
func Wait(w io.Writer, message string) { statusLine(w, "·", "[wait]", "\x1b[33m", message) }

// Warn writes a non-fatal warning line to w.
func Warn(w io.Writer, message string) { statusLine(w, "!", "[warn]", "\x1b[33m", message) }

// Fail writes a failure line to w.
func Fail(w io.Writer, message string) { statusLine(w, "✗", "[error]", "\x1b[31m", message) }

// Info writes a plain informational line to w.
func Info(w io.Writer, message string) { fmt.Fprintln(w, message) }

// Duration formats d in whole seconds using compact readable units.
func Duration(d time.Duration) string {
	total := int64(d / time.Second)
	if total <= 0 {
		return "0s"
	}
	var parts []string
	if h := total / 3600; h > 0 {
		parts = append(parts, fmt.Sprintf("%dh", h))
	}
	if m := (total % 3600) / 60; m > 0 {
		parts = append(parts, fmt.Sprintf("%dm", m))
	}
	if s := total % 60; s > 0 {
		parts = append(parts, fmt.Sprintf("%ds", s))
	}
	return strings.Join(parts, " ")
}

// UTC formats a Unix timestamp in seconds as a readable UTC timestamp.
func UTC(unix int64) string {
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04:05 UTC")
}

// Field writes an aligned label/value pair to w.
func Field(w io.Writer, label, value string) {
	padded := fmt.Sprintf("%-18s", label)
	if ColorEnabled(w) {
		fmt.Fprintf(w, "\x1b[2m%s\x1b[0m %s\n", padded, value)
		return
	}
	fmt.Fprintf(w, "%s %s\n", padded, value)
}
