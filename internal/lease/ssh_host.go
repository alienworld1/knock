package lease

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func (h *Host) makeCredentials(g Grant) (Connection, error) {
	conn := Connection{Endpoint: h.endpoint.String(), ServerKey: h.key}
	rand.Read(conn.PSK[:])
	userKey, err := ssh.NewPublicKey(ed25519.PublicKey(g.SSH[:]))
	if err != nil {
		return conn, err
	}
	_, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return conn, err
	}
	defer clear(caKey)
	ca, err := ssh.NewSignerFromKey(caKey)
	if err != nil {
		return conn, err
	}
	certificate := &ssh.Certificate{
		Key: userKey, CertType: ssh.UserCert, KeyId: principal(g.ID),
		ValidPrincipals: []string{principal(g.ID)},
		ValidAfter:      uint64(time.Now().Add(-5 * time.Second).Unix()), ValidBefore: uint64(g.Deadline.Unix()),
		Permissions: ssh.Permissions{CriticalOptions: map[string]string{"source-address": ClientIP + "/32"}},
	}
	if err := certificate.SignCert(rand.Reader, ca); err != nil {
		return conn, err
	}
	hostKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return conn, err
	}
	defer clear(privateKey)
	host, err := ssh.NewPublicKey(hostKey)
	if err != nil {
		return conn, err
	}
	conn.HostKey, conn.Certificate = host.Marshal(), certificate.Marshal()
	block, err := ssh.MarshalPrivateKey(privateKey, "")
	if err != nil {
		return conn, err
	}
	defer clear(block.Bytes)
	pemKey := pem.EncodeToMemory(block)
	defer clear(pemKey)
	if err := os.Mkdir(filepath.Join(private, g.ID), 0700); err != nil {
		return conn, err
	}
	if err := os.WriteFile(filepath.Join(private, g.ID, "host"), pemKey, 0600); err != nil {
		return conn, err
	}
	if err := os.WriteFile(filepath.Join(private, g.ID, "ca.pub"), ssh.MarshalAuthorizedKey(ca.PublicKey()), 0600); err != nil {
		return conn, err
	}
	if err := os.WriteFile(filepath.Join(public, g.ID), []byte(principal(g.ID)+"\n"), 0644); err != nil {
		return conn, err
	}
	return conn, nil
}

const sshdConfig = `AddressFamily inet
ListenAddress %s:%d
PidFile none
HostKey %s/host
TrustedUserCAKeys %s/ca.pub
AuthorizedPrincipalsFile %s/%s
AuthorizedKeysFile none
AuthenticationMethods publickey
PubkeyAcceptedAlgorithms ssh-ed25519-cert-v01@openssh.com
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers knockssh
UsePAM no
DisableForwarding yes
PermitTunnel no
PermitUserRC no
PermitUserEnvironment no
PermitTTY no
PrintMotd no
MaxSessions 1
LogLevel INFO
ForceCommand %s ssh-role %s %s
`

func startSSH(ctx context.Context, g Grant) error {
	dir := filepath.Join(private, g.ID)
	config := filepath.Join(dir, "sshd_config")
	content := fmt.Sprintf(sshdConfig, ServerIP, SSHPort, dir, dir, public, g.ID, daemonPath, g.Role, g.ID)
	if err := os.WriteFile(config, []byte(content), 0600); err != nil {
		return err
	}
	effective, err := native(ctx, nil, sshdPath, "-T", "-f", config)
	if err != nil {
		return err
	}
	lines := strings.Split(string(effective), "\n")
	for _, setting := range []string{
		"listenaddress " + fmt.Sprintf("%s:%d", ServerIP, SSHPort),
		"authorizedprincipalsfile " + filepath.Join(public, g.ID),
		"trustedusercakeys " + filepath.Join(dir, "ca.pub"),
		"forcecommand " + daemonPath + " ssh-role " + g.Role + " " + g.ID,
		"allowusers " + User, "usepam no", "disableforwarding yes", "permitrootlogin no",
		"authorizedkeysfile none", "authenticationmethods publickey", "permittty no", "permituserrc no",
	} {
		if !slices.Contains(lines, setting) {
			return fmt.Errorf("the effective SSH configuration is missing %q", strings.Fields(setting)[0])
		}
	}
	remaining := time.Until(g.Deadline).Microseconds()
	if remaining <= 0 {
		return errors.New("the session deadline passed during provisioning")
	}
	if err := run(ctx, systemdRunPath, "--quiet", "--unit="+unit(g.ID), "--collect", "--service-type=exec",
		fmt.Sprintf("--property=RuntimeMaxSec=%dus", remaining),
		"--property=KillMode=control-group", "--property=KillSignal=SIGKILL", "--property=TimeoutStopSec=1s",
		"--property=Delegate=no", "--property=TasksMax=48", "--property=LimitCORE=0",
		"--property=NoNewPrivileges=yes", "--property=ProtectSystem=strict", "--property=PrivateTmp=yes",
		"--property=ProtectHome=yes", "--property=ProtectControlGroups=yes", "--property=ProtectKernelTunables=yes",
		"--property=RestrictSUIDSGID=yes",
		sshdPath, "-D", "-e", "-f", config); err != nil {
		return err
	}
	for range 20 {
		listening, err := listener(ctx)
		if err != nil || listening {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return errors.New("the protected SSH listener didn't start")
}

func listener(ctx context.Context) (bool, error) {
	out, err := native(ctx, nil, "/usr/bin/ss", "-ltnH", "sport", "=", fmt.Sprint(SSHPort))
	if err != nil {
		return false, err
	}
	return slices.Contains(strings.Fields(string(out)), fmt.Sprintf("%s:%d", ServerIP, SSHPort)), nil
}

func stopSSH(ctx context.Context, id string) error {
	service := unit(id) + ".service"
	stop := run(ctx, systemctlPath, "stop", service)
	state, err := native(ctx, nil, systemctlPath, "show", "--property=ActiveState", "--value", service)
	if err != nil || (strings.TrimSpace(string(state)) != "inactive" && strings.TrimSpace(string(state)) != "failed") {
		stop = errors.Join(stop, err, errors.New("couldn't verify that the SSH service stopped"))
	} else {
		stop = nil
	}
	for _, path := range []string{filepath.Join(public, id), filepath.Join(private, id)} {
		if err := os.RemoveAll(path); err != nil {
			stop = errors.Join(stop, err)
		}
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			stop = errors.Join(stop, errors.New("SSH credentials remain"))
		}
	}
	listening, err := listener(ctx)
	if err != nil || listening {
		stop = errors.Join(stop, err, errors.New("couldn't verify removal of the protected SSH listener"))
	}
	group := filepath.Join("/sys/fs/cgroup/system.slice", service, "cgroup.events")
	events, err := os.ReadFile(group)
	if !errors.Is(err, os.ErrNotExist) && (err != nil || !slices.Contains(strings.Split(string(events), "\n"), "populated 0")) {
		stop = errors.Join(stop, err, errors.New("SSH cgroup still has processes or couldn't be verified"))
	}
	return stop
}
