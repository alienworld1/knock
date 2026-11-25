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
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

const clientPath = "/usr/local/bin/knock"
const sudoPath = "/usr/bin/sudo"

type Streams struct {
	In          io.Reader
	Out, Err    io.Writer
	OnConnected func()
}

var ErrClientCleanup = errors.New("couldn't remove all local connection resources")

type tunnelSpec struct {
	PrivateKey [32]byte
	Peer       [32]byte
	PSK        [32]byte
	Endpoint   string
	Slot       uint8
}

func Connect(ctx context.Context, wg []byte, key ed25519.PrivateKey, conn Connection, deadline time.Time, streams Streams) (err error) {
	defer clear(conn.PSK[:])
	assigned := slot(conn.Slot)
	if !assigned.valid() {
		return errors.New("invalid SSH slot")
	}
	dir, name, guard, err := prepareClientRuntime(ctx)
	if err != nil {
		return err
	}
	defer guard.Close()
	defer func() { err = errors.Join(err, clientCleanup(cleanClientRuntime(dir))) }()
	if !conn.HTTP {
		if err := writeClientSSH(dir, key, conn); err != nil {
			return err
		}
	}
	payload := tunnelSpec{PrivateKey: [32]byte(wg), Peer: conn.ServerKey, PSK: conn.PSK, Endpoint: conn.Endpoint, Slot: conn.Slot}
	raw, err := json.Marshal(payload)
	clear(payload.PrivateKey[:])
	clear(payload.PSK[:])
	if err != nil {
		return err
	}
	defer clear(raw)
	if !time.Now().Before(deadline) {
		return errors.New("the connection deadline passed")
	}
	// Let the bounded helper finish setting up or rolling back before removing its link.
	setup := exec.Command(sudoPath, "-n", clientPath, "tunnel-up", name)
	setup.Stdin = bytes.NewReader(raw)
	setup.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
	if err := setup.Run(); err != nil {
		return errors.New("couldn't prepare WireGuard. Check the Knock tunnel permissions.")
	}
	clear(raw)
	call, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if conn.HTTP {
		return connectHTTP(call, assigned, streams)
	}
	cmd := exec.CommandContext(call, "/usr/bin/ssh", "-F", "/dev/null", "-T",
		"-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none",
		"-o", "CertificateFile="+filepath.Join(dir, "client-cert.pub"),
		"-o", "StrictHostKeyChecking=yes", "-o", "GlobalKnownHostsFile=/dev/null",
		"-o", "UserKnownHostsFile="+filepath.Join(dir, "known_hosts"),
		"-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "UpdateHostKeys=no",
		"-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=5",
		"-o", "ServerAliveInterval=2", "-o", "ServerAliveCountMax=2",
		"-o", "PermitLocalCommand=yes", "-o", "LocalCommand=/usr/bin/printf 'Connected.\\n' >&2",
		"-i", filepath.Join(dir, "client"), "-p", strconv.Itoa(assigned.port()), assigned.user()+"@"+ServerIP)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
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

func prepareClientRuntime(ctx context.Context) (dir, name string, guard *os.File, err error) {
	uid := os.Getuid()
	parent := filepath.Join("/run/user", strconv.Itoa(uid))
	var fs unix.Statfs_t
	if !privateClientDir(parent, uid) || unix.Statfs(parent, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return "", "", nil, errors.New("open a Linux login session with a private runtime directory")
	}
	root := filepath.Join(parent, "knock-client")
	if err := os.Mkdir(root, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", "", nil, err
	}
	if !privateClientDir(root, uid) {
		return "", "", nil, errors.New("couldn't verify the Knock client runtime directory")
	}
	lock, err := lockFile(filepath.Join(root, "connection.lock"), true)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return "", "", nil, errors.New("another Knock SSH connection is using this login session")
	}
	if err != nil {
		return "", "", nil, err
	}
	defer func() {
		if err != nil {
			lock.Close()
		}
	}()
	dir = filepath.Join(root, "ssh")
	if info, err := os.Lstat(dir); err == nil {
		if !info.IsDir() || !privateClientDir(dir, uid) {
			return "", "", nil, errors.New("couldn't verify the previous Knock client runtime directory")
		}
		if err := cleanClientRuntime(dir); err != nil {
			return "", "", nil, clientCleanup(err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", nil, err
	}
	if err := cleanOwnedClientLinks(ctx, uid); err != nil {
		return "", "", nil, clientCleanup(err)
	}
	if err := ctx.Err(); err != nil {
		return "", "", nil, err
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		return "", "", nil, err
	}
	var suffix [6]byte
	rand.Read(suffix[:])
	name = "kc" + hex.EncodeToString(suffix[:])
	if err := os.WriteFile(filepath.Join(dir, "link"), []byte(name), 0600); err != nil {
		return "", "", nil, errors.Join(err, os.Remove(dir))
	}
	return dir, name, lock, nil
}

func privateClientDir(path string, uid int) bool {
	var stat unix.Stat_t
	return unix.Lstat(path, &stat) == nil && stat.Uid == uint32(uid) && stat.Mode == unix.S_IFDIR|0700
}

// Login cleanup can remove /run/user before the kernel drops its WireGuard
// links. The user-wide lock serializes supported Knock connections.
func cleanOwnedClientLinks(ctx context.Context, uid int) error {
	links, err := clientLinks(ctx)
	if err != nil {
		return err
	}
	for _, link := range links {
		if validTunnelName(link.Name) && link.Alias == clientAlias(uint64(uid)) {
			if err := run(ctx, sudoPath, "-n", clientPath, "tunnel-down", link.Name); err != nil {
				return err
			}
		}
	}
	return nil
}

func cleanClientRuntime(dir string) error {
	var failure error
	for _, path := range []string{"client", "client-cert.pub", "known_hosts"} {
		if err := os.Remove(filepath.Join(dir, path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			failure = errors.Join(failure, err)
		}
	}
	marker := filepath.Join(dir, "link")
	var stat unix.Stat_t
	if err := unix.Lstat(marker, &stat); errors.Is(err, os.ErrNotExist) {
		return errors.Join(failure, os.Remove(dir))
	} else if err != nil || stat.Mode != unix.S_IFREG|0600 || stat.Size != 14 || stat.Uid != uint32(os.Getuid()) {
		return errors.Join(failure, errors.New("invalid local Knock tunnel ownership record"))
	}
	link, err := os.ReadFile(marker)
	if err != nil {
		return errors.Join(failure, err)
	}
	if !validTunnelName(string(link)) {
		return errors.Join(failure, errors.New("invalid local Knock tunnel name"))
	}
	stop, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := run(stop, sudoPath, "-n", clientPath, "tunnel-down", string(link)); err != nil {
		return errors.Join(failure, err)
	}
	if failure != nil {
		return failure
	}
	return errors.Join(os.Remove(marker), os.Remove(dir))
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
		os.WriteFile(filepath.Join(dir, "known_hosts"), fmt.Appendf(nil, "[%s]:%d %s", ServerIP, slot(conn.Slot).port(), ssh.MarshalAuthorizedKey(host)), 0600),
	)
}
