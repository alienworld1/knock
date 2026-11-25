package lease

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const clientPath = "/usr/local/bin/knock"
const sudoPath = "/usr/bin/sudo"

type Streams struct {
	In       io.Reader
	Out, Err io.Writer
}

var ErrClientCleanup = errors.New("couldn't remove all local connection resources")

type tunnelSpec struct {
	PrivateKey [32]byte
	Peer       [32]byte
	PSK        [32]byte
	Endpoint   string
}

func Connect(ctx context.Context, wg []byte, key ed25519.PrivateKey, conn Connection, deadline time.Time, streams Streams) (err error) {
	defer clear(conn.PSK[:])
	dir, err := clientRuntime()
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, clientCleanup(os.RemoveAll(dir))) }()
	if err := writeClientSSH(dir, key, conn); err != nil {
		return err
	}
	var suffix [6]byte
	rand.Read(suffix[:])
	name := "kc" + hex.EncodeToString(suffix[:])
	payload := tunnelSpec{PrivateKey: [32]byte(wg), Peer: conn.ServerKey, PSK: conn.PSK, Endpoint: conn.Endpoint}
	raw, err := json.Marshal(payload)
	clear(payload.PrivateKey[:])
	clear(payload.PSK[:])
	if err != nil {
		return err
	}
	defer clear(raw)
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		err = errors.Join(err, clientCleanup(run(stop, sudoPath, "-n", clientPath, "tunnel-down", name)))
	}()
	if !time.Now().Before(deadline) {
		return errors.New("the connection deadline passed")
	}
	// Let the bounded helper finish setting up or rolling back before removing its link.
	setup := exec.Command(sudoPath, "-n", clientPath, "tunnel-up", name)
	setup.Stdin = bytes.NewReader(raw)
	if err := setup.Run(); err != nil {
		return errors.New("couldn't prepare WireGuard. Check the Knock tunnel permissions.")
	}
	clear(raw)
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	cmd := exec.CommandContext(call, "/usr/bin/ssh", "-F", "/dev/null", "-T",
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
		"-o", "CertificateFile="+filepath.Join(dir, "client-cert.pub"),
		"-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile="+filepath.Join(dir, "known_hosts"),
		"-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "UpdateHostKeys=no",
		"-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=5",
		"-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=2",
		"-o", "PermitLocalCommand=yes", "-o", "LocalCommand=/usr/bin/printf 'Connected.\\n' >&2",
		"-i", filepath.Join(dir, "client"), "-p", strconv.Itoa(SSHPort), User+"@"+ServerIP)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = streams.In, streams.Out, streams.Err
	err = cmd.Run()
	if errors.Is(call.Err(), context.DeadlineExceeded) {
		return errors.New("connection deadline reached")
	}
	return err
}

func clientCleanup(err error) error {
	if err != nil {
		return ErrClientCleanup
	}
	return nil
}

func clientRuntime() (string, error) {
	uid := os.Getuid()
	parent := filepath.Join("/run/user", strconv.Itoa(uid))
	var stat unix.Stat_t
	var fs unix.Statfs_t
	if unix.Lstat(parent, &stat) != nil || stat.Uid != uint32(uid) ||
		stat.Mode != unix.S_IFDIR|0700 || unix.Statfs(parent, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return "", errors.New("open a Linux login session with a private runtime directory")
	}
	return os.MkdirTemp(parent, "knock-")
}

func writeClientSSH(dir string, key ed25519.PrivateKey, conn Connection) error {
	host, err := ssh.ParsePublicKey(conn.HostKey)
	if err != nil {
		return err
	}
	cert, err := ssh.ParsePublicKey(conn.Certificate)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(key, "")
	if err != nil {
		return err
	}
	defer clear(block.Bytes)
	privateKey := pem.EncodeToMemory(block)
	defer clear(privateKey)
	return errors.Join(
		os.WriteFile(filepath.Join(dir, "client"), privateKey, 0600),
		os.WriteFile(filepath.Join(dir, "client-cert.pub"), ssh.MarshalAuthorizedKey(cert), 0600),
		os.WriteFile(filepath.Join(dir, "known_hosts"), fmt.Appendf(nil, "[%s]:%d %s", ServerIP, SSHPort, ssh.MarshalAuthorizedKey(host)), 0600),
	)
}
