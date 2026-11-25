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
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	base           = "/run/knock-ssh"
	private        = base + "/private"
	public         = base + "/principals"
	manifests      = private + "/sessions"
	legacyManifest = private + "/slot.json"
)

type manifest struct {
	ID       string
	Peer     [32]byte
	Deadline time.Time
	Slot     slot
	State    State
	Cause    string
	HTTP     bool
}

var ErrDoorLocked = errors.New("the Knock SSH Door lock is in use")

type Host struct {
	lock     *os.File
	endpoint netip.AddrPort
	key      [32]byte
	slots    [slotCount]bool
	http     bool
}

func StartHost(ctx context.Context, value string, metered bool) (_ *Host, err error) {
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
		{base, 0755}, {private, 0700}, {manifests, 0700}, {public, 0755}, {"/run/sshd", 0755},
	} {
		if err := rootDir(dir.path, dir.mode); err != nil {
			return nil, err
		}
	}
	lock, err := lockFile(private+"/door.lock", true)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return nil, ErrDoorLocked
	}
	if err != nil {
		return nil, fmt.Errorf("acquire the Door SSH lock: %w", err)
	}
	defer func() {
		if err != nil {
			lock.Close()
		}
	}()
	mutation, err := lockSlots(ctx)
	if err != nil {
		return nil, err
	}
	defer mutation.Close()
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
	instance := &Host{lock: lock, endpoint: endpoint, http: metered}
	if err := migrateManifest(); err != nil {
		return nil, err
	}
	if err := closeAll(ctx, "Door restarted"); err != nil {
		return nil, err
	}
	if err := verifyNoOrphans(ctx); err != nil {
		return nil, err
	}
	if metered {
		for i := range instance.slots {
			instance.slots[i] = true
		}
	} else {
		if err := instance.loadAccounts(); err != nil {
			return nil, err
		}
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
	if err := setupClientRoute(ctx); err != nil {
		return nil, err
	}
	return instance, nil
}

func setupClientRoute(ctx context.Context) error {
	raw, err := native(ctx, nil, ipPath, "-j", "route", "show", "exact", clientNetwork)
	if err != nil {
		return err
	}
	var routes []struct {
		Device string `json:"dev"`
		Source string `json:"prefsrc"`
	}
	if err := json.Unmarshal(raw, &routes); err != nil {
		return err
	}
	if len(routes) == 0 {
		return run(ctx, ipPath, "route", "add", clientNetwork, "dev", device, "src", ServerIP)
	}
	if len(routes) != 1 || routes[0].Device != device || routes[0].Source != ServerIP {
		return errors.New("the reserved Knock client network already has another route")
	}
	return nil
}

func (h *Host) loadAccounts() error {
	uids := make(map[string]bool)
	for assigned := slot(0); assigned.valid(); assigned++ {
		account, err := user.Lookup(assigned.user())
		var missing user.UnknownUserError
		if errors.As(err, &missing) {
			continue
		}
		if err != nil {
			return err
		}
		if account.Uid == "0" || uids[account.Uid] {
			return errors.New("Knock SSH slots require distinct non-root accounts")
		}
		uids[account.Uid], h.slots[assigned] = true, true
	}
	if len(uids) == 0 {
		return errors.New("create at least one local Knock SSH account")
	}
	return nil
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

func lockSlots(ctx context.Context) (*os.File, error) {
	for {
		file, err := lockFile(private+"/slot.lock", true)
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return file, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func manifestPath(id string) string { return filepath.Join(manifests, id+".json") }

func readManifest(path string) (manifest, error) {
	var m manifest
	raw, err := os.ReadFile(path)
	if err != nil {
		return m, err
	}
	if json.Unmarshal(raw, &m) != nil || !validID(m.ID) || !m.Slot.valid() ||
		m.Peer == ([32]byte{}) || m.Deadline.IsZero() ||
		(path != legacyManifest && path != manifestPath(m.ID)) {
		return m, errors.New("invalid Knock cleanup record")
	}
	switch m.State {
	case Provisioning, Ready, Active, Closing, Closed, CleanupIncomplete:
		return m, nil
	default:
		return m, errors.New("invalid Knock cleanup state")
	}
}

func migrateManifest() error {
	m, err := readManifest(legacyManifest)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	// A crash between writing the replacement and deleting the old file must
	// leave the most recent record authoritative.
	if _, err := readManifest(manifestPath(m.ID)); errors.Is(err, os.ErrNotExist) {
		if err := saveManifest(m); err != nil {
			return err
		}
	} else if err != nil {
		return err
	}
	return os.Remove(legacyManifest)
}

func readManifests() ([]manifest, error) {
	files, err := os.ReadDir(manifests)
	if err != nil {
		return nil, err
	}
	var records []manifest
	var occupied [slotCount]bool
	peers := make(map[[32]byte]bool)
	for _, file := range files {
		// An interrupted atomic replacement can leave its temporary file.
		if strings.HasPrefix(file.Name(), ".session-") {
			continue
		}
		m, err := readManifest(filepath.Join(manifests, file.Name()))
		if err != nil {
			return nil, err
		}
		if m.State != Closed {
			if occupied[m.Slot] || peers[m.Peer] {
				return nil, errors.New("Knock cleanup records claim the same resource")
			}
			occupied[m.Slot], peers[m.Peer] = true, true
		}
		records = append(records, m)
	}
	return records, nil
}

func saveManifest(m manifest) error {
	file, err := os.CreateTemp(manifests, ".session-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(m)
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), manifestPath(m.ID))
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
	if !validID(g.ID) || g.Recheck == nil || g.Confirm == nil || g.WireGuard == ([32]byte{}) ||
		g.HTTP != h.http || (g.HTTP && (g.Role != "" || g.SSH != ([32]byte{}))) ||
		(!g.HTTP && g.Role != "logs" && g.Role != "maintenance") || !time.Now().Before(g.Deadline) {
		return conn, errors.New("invalid connection grant")
	}
	lock, err := lockSlots(ctx)
	if err != nil {
		return conn, err
	}
	owned, issued := false, false
	defer func() {
		if lock != nil {
			_ = lock.Close()
		}
		if owned && !issued {
			clear(conn.PSK[:])
			recovery, cancel := context.WithTimeout(context.Background(), 18*time.Second)
			defer cancel()
			err = errors.Join(err, h.Close(recovery, g.ID))
		}
	}()
	records, err := readManifests()
	if err != nil {
		return conn, err
	}
	var occupied [slotCount]bool
	for i, available := range h.slots {
		occupied[i] = !available
	}
	for _, record := range records {
		if record.ID == g.ID || (record.State != Closed && record.Peer == g.WireGuard) {
			return conn, errors.New("this SSH session or client key already has a cleanup record")
		}
		if record.State != Closed {
			occupied[record.Slot] = true
		}
	}
	free := slices.Index(occupied[:], false)
	if free < 0 {
		return conn, errors.New("all SSH slots are busy or pending cleanup")
	}
	assigned := slot(free)
	if listening, err := listener(ctx, assigned); err != nil || listening {
		return conn, errors.Join(err, errors.New("couldn't verify an unused SSH listener address"))
	}
	m := manifest{ID: g.ID, Peer: g.WireGuard, Deadline: g.Deadline, Slot: assigned, State: Provisioning, HTTP: g.HTTP}
	if err := saveManifest(m); err != nil {
		return conn, err
	}
	owned = true
	if err := armTimer(ctx, g); err != nil {
		return conn, err
	}
	conn, err = h.makeCredentials(g, assigned)
	if err != nil {
		return conn, err
	}
	if err := setWG(ctx, conn.PSK[:], device, "peer", wgText(g.WireGuard[:]), "preshared-key", "/dev/stdin", "allowed-ips", assigned.clientIP()+"/32"); err != nil {
		return conn, err
	}
	start := startSSH
	if g.HTTP {
		start = startHTTP
	}
	if err := start(ctx, g, assigned); err != nil {
		return conn, err
	}
	if err := lock.Close(); err != nil {
		return conn, err
	}
	lock = nil
	check, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = g.Recheck(check)
	cancel()
	if err != nil {
		return conn, err
	}
	lock, err = lockSlots(ctx)
	if err != nil {
		return conn, err
	}
	current, err := readManifest(manifestPath(g.ID))
	if err != nil || current.State != Provisioning {
		return conn, errors.Join(err, errors.New("SSH provisioning ended before permission could be enabled"))
	}
	if err := g.Confirm(); err != nil {
		return conn, err
	}
	if err := enable(ctx, assigned, g.Deadline); err != nil {
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

func (h *Host) CloseAll(ctx context.Context) error {
	lock, err := lockSlots(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	return closeAll(ctx, "Door stopped")
}

func closeAll(ctx context.Context, cause string) error {
	records, err := readManifests()
	if err != nil {
		return err
	}
	var failure error
	for _, m := range records {
		if m.State != Closed {
			failure = errors.Join(failure, closeSlot(ctx, m, cause))
		}
	}
	return failure
}

func verifyNoOrphans(ctx context.Context) error {
	for _, path := range []string{public, private} {
		files, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, file := range files {
			if validID(file.Name()) {
				return errors.New("unowned Knock SSH credentials remain")
			}
		}
	}
	for assigned := slot(0); assigned.valid(); assigned++ {
		if listening, err := listener(ctx, assigned); err != nil || listening {
			return errors.Join(err, errors.New("unowned protected SSH listener or unverifiable listener state"))
		}
	}
	out, err := native(ctx, nil, systemctlPath, "list-units", "--plain", "--no-legend", "--no-pager", "--state=active,activating,deactivating", "knock-ssh-*.service")
	if err != nil || len(strings.TrimSpace(string(out))) != 0 {
		return errors.Join(err, errors.New("unowned Knock SSH unit or unverifiable unit state"))
	}
	return nil
}

func (h *Host) Release() error { return h.lock.Close() }

func (h *Host) Close(ctx context.Context, id string) error { return closeWithLock(ctx, id, "") }

func Expire(ctx context.Context, id string) error {
	if !validID(id) || os.Geteuid() != 0 {
		return errors.New("invalid SSH cleanup authority")
	}
	// A timer from the single-slot release can run before the upgraded Door.
	if err := rootDir(manifests, 0700); err != nil {
		return err
	}
	return closeWithLock(ctx, id, "Expired")
}

func closeWithLock(ctx context.Context, id, cause string) error {
	if !validID(id) {
		return errors.New("invalid SSH cleanup reference")
	}
	lock, err := lockSlots(ctx)
	if err != nil {
		return err
	}
	defer lock.Close()
	m, err := readManifest(manifestPath(id))
	if errors.Is(err, os.ErrNotExist) {
		legacy, legacyErr := readManifest(legacyManifest)
		if errors.Is(legacyErr, os.ErrNotExist) || (legacyErr == nil && legacy.ID != id) {
			return nil
		}
		if legacyErr != nil {
			return legacyErr
		}
		if err := migrateManifest(); err != nil {
			return err
		}
		m, err = readManifest(manifestPath(id))
	}
	if err != nil {
		return err
	}
	if m.State == Closed {
		return nil
	}
	return closeSlot(ctx, m, cause)
}

func closeSlot(ctx context.Context, m manifest, cause string) error {
	m.State = Closing
	if m.Cause == "" {
		m.Cause = cause
	}
	saved := saveManifest(m)
	network := deny(ctx, m.Slot)
	service := stopSSH(ctx, m.ID, m.Slot)
	peer := run(ctx, wgPath, "set", device, "peer", wgText(m.Peer[:]), "remove")
	peers, queried := native(ctx, nil, wgPath, "show", device, "peers")
	if queried == nil && !slices.Contains(strings.Fields(string(peers)), wgText(m.Peer[:])) {
		peer = nil
	} else {
		peer = errors.Join(peer, queried, errors.New("couldn't verify peer removal"))
	}
	err := errors.Join(saved, network, service, peer)
	m.State = Closed
	if err != nil {
		m.State = CleanupIncomplete
	}
	return errors.Join(err, saveManifest(m))
}

type Observation struct {
	State State
	Cause string
}

func (h *Host) Observe(ctx context.Context, id string) (Observation, error) {
	if !validID(id) {
		return Observation{}, errors.New("invalid SSH observation reference")
	}
	lock, err := lockFile(private+"/slot.lock", true)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return Observation{}, nil
	}
	if err != nil {
		return Observation{}, err
	}
	defer lock.Close()
	m, err := readManifest(manifestPath(id))
	if errors.Is(err, os.ErrNotExist) {
		return Observation{}, nil
	}
	if err != nil {
		return Observation{}, err
	}
	if m.State == Ready && time.Now().Before(m.Deadline) {
		pattern := "^Accepted publickey for " + m.Slot.user() + " from " + regexp.QuoteMeta(m.Slot.clientIP()) + " port "
		if m.HTTP {
			pattern = "^Served private HTTP request from " + regexp.QuoteMeta(m.Slot.clientIP()) + "$"
		}
		out, err := native(ctx, nil, journalPath, "--no-pager", "--quiet", "--output=cat", "--lines=1",
			"--unit="+unit(m.ID)+".service", "--grep="+pattern)
		if err == nil && len(out) > 0 {
			m.State = Active
			if err := saveManifest(m); err != nil {
				return Observation{}, err
			}
		}
	}
	return Observation{m.State, m.Cause}, nil
}
