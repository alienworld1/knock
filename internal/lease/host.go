package lease

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	base         = "/run/knock-ssh"
	private      = base + "/private"
	public       = base + "/principals"
	manifestPath = private + "/slot.json"
)

type manifest struct {
	ID       string
	Peer     [32]byte
	Deadline time.Time
	State    State
}

type Host struct {
	lock     *os.File
	endpoint netip.AddrPort
	key      [32]byte
}

func StartHost(ctx context.Context, value string) (_ *Host, err error) {
	endpoint, err := ValidateEndpoint(value)
	if err != nil {
		return nil, err
	}
	if os.Geteuid() != 0 {
		return nil, errors.New("start SSH access from the root-managed Knock Door service")
	}
	var fs unix.Statfs_t
	if unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return nil, errors.New("SSH access requires a tmpfs-backed /run")
	}
	for _, dir := range []struct {
		path string
		mode os.FileMode
	}{
		{base, 0755}, {private, 0700}, {public, 0755}, {"/run/sshd", 0755},
	} {
		if err := rootDir(dir.path, dir.mode); err != nil {
			return nil, err
		}
	}
	lock, err := lockFile(private+"/door.lock", true)
	if err != nil {
		return nil, fmt.Errorf("acquire the Door SSH lock: %w", err)
	}
	defer func() {
		if err != nil {
			lock.Close()
		}
	}()
	tables, err := native(ctx, nil, nftPath, "list", "tables")
	if err != nil {
		return nil, err
	}
	links, err := native(ctx, nil, ipPath, "-j", "link", "show")
	if err != nil {
		return nil, err
	}
	hasTable := slices.Contains(strings.Split(string(tables), "\n"), "table inet "+table)
	var interfaces []struct {
		Name  string `json:"ifname"`
		Alias string `json:"ifalias"`
	}
	if err := json.Unmarshal(links, &interfaces); err != nil {
		return nil, err
	}
	hasDevice := false
	for _, link := range interfaces {
		if link.Name == device {
			if link.Alias != "Knock Door" {
				return nil, errors.New("the WireGuard interface name is already in use")
			}
			hasDevice = true
		}
	}
	owner := private + "/firewall-owned"
	if _, err := os.Stat(owner); errors.Is(err, os.ErrNotExist) {
		if hasTable || hasDevice {
			return nil, errors.New("Knock network resources already exist without an ownership record")
		}
		if err := os.WriteFile(owner, nil, 0600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	if hasTable {
		// Replace this Door's table in one transaction. Never leave an open gap.
		if err := nft(ctx, "delete table inet "+table+"\n"+firewall); err != nil {
			return nil, err
		}
	} else if err := nft(ctx, firewall); err != nil {
		return nil, err
	}
	if !hasDevice {
		if err := run(ctx, ipPath, "link", "add", "name", device, "type", "wireguard"); err != nil {
			return nil, err
		}
		if err := run(ctx, ipPath, "link", "set", "dev", device, "alias", "Knock Door"); err != nil {
			remove := run(ctx, ipPath, "link", "delete", device)
			return nil, errors.Join(err, remove)
		}
	}
	if err := run(ctx, ipPath, "address", "replace", ServerIP+"/32", "dev", device); err != nil {
		return nil, err
	}
	instance := &Host{lock: lock, endpoint: endpoint}
	if err := instance.CloseCurrent(ctx); err != nil {
		return nil, err
	}
	peers, err := native(ctx, nil, wgPath, "show", device, "peers")
	if err != nil || len(strings.Fields(string(peers))) != 0 {
		return nil, errors.New("couldn't verify an empty Knock WireGuard interface")
	}
	keys, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	secret := keys.Bytes()
	defer clear(secret)
	if err := setWG(ctx, secret, device, "listen-port", fmt.Sprint(endpoint.Port()), "private-key", "/dev/stdin"); err != nil {
		return nil, err
	}
	copy(instance.key[:], keys.PublicKey().Bytes())
	if err := run(ctx, ipPath, "link", "set", "dev", device, "up"); err != nil {
		return nil, err
	}
	if err := run(ctx, ipPath, "route", "replace", ClientIP+"/32", "dev", device, "src", ServerIP); err != nil {
		return nil, err
	}
	return instance, nil
}

func rootDir(path string, mode os.FileMode) error {
	if err := os.Mkdir(path, mode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	var info unix.Stat_t
	if err := unix.Lstat(path, &info); err != nil {
		return err
	}
	if info.Uid != 0 || info.Mode&unix.S_IFMT != unix.S_IFDIR || os.FileMode(info.Mode&0777) != mode {
		return fmt.Errorf("expected root-owned directory %s with permissions %04o", path, mode)
	}
	return nil
}

func lockFile(path string, nonblocking bool) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	op := unix.LOCK_EX
	if nonblocking {
		op |= unix.LOCK_NB
	}
	if err := unix.Flock(int(file.Fd()), op); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

func readManifest() (manifest, error) {
	var m manifest
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return m, err
	}
	if json.Unmarshal(raw, &m) != nil || !validID(m.ID) || m.Peer == ([32]byte{}) || m.Deadline.IsZero() {
		return m, errors.New("invalid Knock cleanup record")
	}
	switch m.State {
	case Provisioning, Ready, Active, Closing, Closed, CleanupIncomplete:
		return m, nil
	default:
		return m, errors.New("invalid Knock cleanup state")
	}
}

func saveManifest(m manifest) error {
	file, err := os.CreateTemp(private, "slot.*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(m)
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), manifestPath)
}

func wgText(key []byte) string { return base64.StdEncoding.EncodeToString(key) }

func setWG(ctx context.Context, key []byte, args ...string) error {
	input := make([]byte, base64.StdEncoding.EncodedLen(len(key))+1)
	defer clear(input)
	base64.StdEncoding.Encode(input, key)
	input[len(input)-1] = '\n'
	_, err := native(ctx, input, wgPath, append([]string{"set"}, args...)...)
	return err
}

func unit(id string) string  { return "knock-ssh-" + id }
func timer(id string) string { return "knock-expire-" + id }

func (h *Host) Provision(ctx context.Context, g Grant) (conn Connection, err error) {
	if !validID(g.ID) || g.Recheck == nil || g.WireGuard == ([32]byte{}) ||
		(g.Role != "logs" && g.Role != "maintenance") || !time.Now().Before(g.Deadline) {
		return conn, errors.New("invalid SSH grant")
	}
	lock, err := lockFile(private+"/slot.lock", false)
	if err != nil {
		return conn, err
	}
	defer lock.Close()
	old, err := readManifest()
	if !errors.Is(err, os.ErrNotExist) && (err != nil || old.State != Closed) {
		return conn, errors.New("the SSH slot is busy or cleanup is incomplete")
	}
	m := manifest{ID: g.ID, Peer: g.WireGuard, Deadline: g.Deadline, State: Provisioning}
	if err := saveManifest(m); err != nil {
		return conn, err
	}
	issued := false
	defer func() {
		if !issued {
			clear(conn.PSK[:])
			recovery, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			err = errors.Join(err, closeSlot(recovery, m))
		}
	}()
	if err := armTimer(ctx, g); err != nil {
		return conn, err
	}
	conn, err = h.makeCredentials(g)
	if err != nil {
		return conn, err
	}
	if err := setWG(ctx, conn.PSK[:], device, "peer", wgText(g.WireGuard[:]), "preshared-key", "/dev/stdin", "allowed-ips", ClientIP+"/32"); err != nil {
		return conn, err
	}
	if err := startSSH(ctx, g); err != nil {
		return conn, err
	}
	if err := g.Recheck(ctx); err != nil {
		return conn, err
	}
	if err := enable(ctx, g.Deadline); err != nil {
		return conn, err
	}
	m.State = Ready
	if err := saveManifest(m); err != nil {
		return conn, err
	}
	issued = true
	return conn, nil
}

func armTimer(ctx context.Context, g Grant) error {
	var clock unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &clock); err != nil {
		return err
	}
	remaining := time.Until(g.Deadline)
	if remaining <= 0 {
		return errors.New("the session deadline passed during provisioning")
	}
	at := clock.Nano()/1000 + remaining.Microseconds()
	return run(ctx, systemdRunPath, "--quiet", "--unit="+timer(g.ID), "--collect",
		fmt.Sprintf("--on-boot=%dus", at), "--timer-property=AccuracySec=1ms", "--property=LimitCORE=0",
		daemonPath, "expire-ssh", g.ID)
}

func (h *Host) CloseCurrent(ctx context.Context) error {
	return closeWithLock(ctx, "")
}

func (h *Host) Release() error { return h.lock.Close() }

func (h *Host) Close(ctx context.Context, id string) error {
	return closeWithLock(ctx, id)
}

func Expire(ctx context.Context, id string) error {
	if !validID(id) || os.Geteuid() != 0 {
		return errors.New("invalid SSH cleanup authority")
	}
	return closeWithLock(ctx, id)
}

func closeWithLock(ctx context.Context, id string) error {
	lock, err := lockFile(private+"/slot.lock", false)
	if err != nil {
		return err
	}
	defer lock.Close()
	m, err := readManifest()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if (id != "" && m.ID != id) || m.State == Closed {
		return nil
	}
	return closeSlot(ctx, m)
}

func closeSlot(ctx context.Context, m manifest) error {
	m.State = Closing
	saved := saveManifest(m)
	network := deny(ctx)
	service := stopSSH(ctx, m.ID)
	peer := run(ctx, wgPath, "set", device, "peer", wgText(m.Peer[:]), "remove")
	// Removal can race with a provisioner that failed before creating the peer.
	peers, queried := native(ctx, nil, wgPath, "show", device, "peers")
	if queried == nil && !slices.Contains(strings.Fields(string(peers)), wgText(m.Peer[:])) {
		peer = nil
	} else {
		peer = errors.Join(peer, queried, errors.New("couldn't verify peer removal"))
	}
	permits := denyVerified(ctx)
	if permits == nil {
		network = nil
	}
	err := errors.Join(saved, network, permits, service, peer)
	m.State = Closed
	if err != nil {
		m.State = CleanupIncomplete
	}
	return errors.Join(err, saveManifest(m))
}

func (h *Host) Observe(ctx context.Context) (string, State, error) {
	lock, err := lockFile(private+"/slot.lock", true)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	defer lock.Close()
	m, err := readManifest()
	if errors.Is(err, os.ErrNotExist) {
		return "", "", nil
	}
	if err != nil {
		return "", "", err
	}
	if m.State == Ready && time.Now().Before(m.Deadline) {
		out, err := native(ctx, nil, journalPath, "--no-pager", "--quiet", "--output=cat", "--lines=1",
			"--unit="+unit(m.ID)+".service", `--grep=^Accepted publickey for knockssh from 198\.19\.0\.2 port `)
		if err == nil && len(out) > 0 {
			m.State = Active
			if err := saveManifest(m); err != nil {
				return "", "", err
			}
		}
	}
	return m.ID, m.State, nil
}
