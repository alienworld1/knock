package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"knock/internal/identity"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type failure struct {
	code int
	err  error
}

func (e failure) Error() string {
	if e.err == nil {
		return ""
	}
	return e.err.Error()
}
func (e failure) Unwrap() error { return e.err }

func Exit(code int, err error) error {
	if err == nil {
		return nil
	}
	return failure{code: code, err: err}
}

func SilentExit(code int) error { return failure{code: code} }

func Run(root *cobra.Command) int {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		fmt.Fprintln(os.Stderr, "couldn't disable core dumps")
		return 8
	}
	root.SilenceUsage = true
	root.SilenceErrors = true
	root.CompletionOptions.DisableDefaultCmd = true
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := root.ExecuteContext(ctx); err != nil {
		if err.Error() != "" {
			fmt.Fprintln(os.Stderr, err)
		}
		var exit failure
		if errors.As(err, &exit) {
			return exit.code
		}
		return 2
	}
	return 0
}

func Home() string {
	path, err := os.UserConfigDir()
	if err != nil || !filepath.IsAbs(path) {
		return ""
	}
	return filepath.Join(path, "knock")
}

func Prompt(label string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("unlock the identity from a terminal")
	}
	fmt.Fprint(os.Stderr, label+" ")
	value, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil || len(value) == 0 {
		clear(value)
		return nil, errors.New("couldn't read a passphrase")
	}
	return value, nil
}

func NewPassphrase() ([]byte, error) {
	one, err := Prompt("New identity passphrase")
	if err != nil {
		return nil, err
	}
	two, err := Prompt("Repeat passphrase")
	defer clear(two)
	if err != nil || !bytes.Equal(one, two) {
		clear(one)
		return nil, errors.New("passphrases did not match")
	}
	return one, nil
}

func Unlock(path, label string) (*identity.Keys, error) {
	if path == "" {
		return nil, errors.New("set an identity profile path")
	}
	value, err := Prompt(label)
	if err != nil {
		return nil, err
	}
	defer clear(value)
	return identity.Unlock(path, value)
}

func SystemdUnlock(path string) (*identity.Keys, error) {
	directory := os.Getenv("CREDENTIALS_DIRECTORY")
	if !filepath.IsAbs(directory) {
		return nil, errors.New("start knockd with its encrypted systemd credential")
	}
	file := filepath.Join(directory, "door-passphrase")
	info, err := os.Lstat(file)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&^0440 != 0 || info.Mode().Perm()&0400 == 0 || info.Size() > 4096 {
		return nil, errors.New("invalid systemd credential file")
	}
	value, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	defer clear(value)
	// systemd-ask-password writes a single trailing newline in interactive setup.
	return identity.Unlock(path, bytes.TrimSuffix(value, []byte("\n")))
}

func Profile(home, flag string) string {
	if flag != "" {
		return flag
	}
	if home == "" {
		return ""
	}
	return filepath.Join(home, "identity.age")
}

func Progress(message string) { fmt.Fprintln(os.Stderr, strings.TrimSpace(message)) }
