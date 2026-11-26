#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 1 ]]; then
  echo 'Usage: deploy/lab/probe.sh LAB_DIRECTORY' >&2
  exit 2
fi
lab=$(realpath -- "$1")
work=$(mktemp -d "$lab/probe.XXXXXXXX")
hosts="$work/known_hosts"
for role_port in door:29221 requester:29222 outsider:29223; do
  role=${role_port%:*}
  port=${role_port#*:}
  awk -v port="$port" '$1 == "ssh-ed25519" {print "[127.0.0.1]:" port, $1, $2; exit}' \
    "$lab/$role/console.log" >> "$hosts"
done
connect() {
  local port=$1
  shift
  ssh -i "$lab/admin" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=5 \
    -o HostKeyAlgorithms=ssh-ed25519 -o "UserKnownHostsFile=$hosts" -o StrictHostKeyChecking=yes \
    -p "$port" lab@127.0.0.1 "$@"
}
door() { connect 29221 "$@"; }
requester() { connect 29222 "$@"; }
outsider() { connect 29223 "$@"; }

for port in 29221 29222 29223; do
  connect "$port" cloud-init status --wait
done

private=''
client_dir=''
cleanup() {
  local result=$? failed=0
  trap - EXIT
  if [[ -n $client_dir ]]; then
    requester "rm -f -- $client_dir/client $client_dir/client-cert.pub $client_dir/wrong-cert.pub $client_dir/protected_hosts $client_dir/raw; rmdir -- $client_dir" || failed=1
  fi
  if [[ -n $private ]]; then
    rm -f -- "$private/client" "$private/client.pub" || failed=1
    rmdir -- "$private" || failed=1
  fi
  door sudo bash -s <<'GUEST' || failed=1
set -e
if systemctl is-active --quiet knock-lab-probe.service; then
  systemctl stop knock-lab-probe.service
fi
if nft list table inet knock_m1 >/dev/null 2>&1; then
  nft delete table inet knock_m1
fi
if ip link show knockwg >/dev/null 2>&1; then
  ip link delete knockwg
fi
rm -rf -- /run/knock-m1 /run/knock-authority
rm -f -- /run/knock-role
GUEST
  requester sudo bash -s <<'GUEST' || failed=1
set -e
if ip link show knockwg >/dev/null 2>&1; then
  ip link delete knockwg
fi
rm -rf -- /run/knock-m1
GUEST
  if (( failed )); then
    echo 'Knock probe cleanup incomplete. Stop the disposable guests before starting a new run.' >&2
    exit 1
  fi
  exit "$result"
}
trap cleanup EXIT

door sudo bash -s <<'GUEST'
set -euo pipefail
umask 077
systemctl stop knock-lab-probe.service 2>/dev/null || true
nft list table inet knock_m1 >/dev/null 2>&1 && nft delete table inet knock_m1
ip link show knockwg >/dev/null 2>&1 && ip link del knockwg
install -d -m 0700 /run/knock-m1
cd /run/knock-m1
test -f ca || ssh-keygen -q -t ed25519 -N '' -f ca
test -f host || ssh-keygen -q -t ed25519 -N '' -f host
test -f wg || wg genkey > wg
wg pubkey < wg > wg.pub
ip link add knockwg type wireguard
ip address add 198.19.0.1/30 dev knockwg
wg set knockwg listen-port 48001 private-key wg
ip link set knockwg up

nft -f - <<'NFT'
table inet knock_m1 {
  set peers {
    type ipv4_addr
    flags timeout
  }
  chain guard {
    type filter hook input priority -20; policy accept;
    iifname { "knocklab1", "knocklab2" } tcp dport 22 drop
    iifname "knockwg" ip saddr @peers tcp dport 2222 accept
    tcp dport 2222 drop
  }
}
NFT
id knockprobe >/dev/null 2>&1 || useradd --system --no-create-home --shell /bin/sh knockprobe
# A non-locking, invalid hash keeps the account eligible for certificate authentication.
usermod --home / --password 'NP' knockprobe
install -d -m 0755 /run/sshd
install -d -m 0755 /run/knock-authority
printf '%s\n' knock-fixture | install -m 0644 /dev/stdin /run/knock-authority/principals
cat > /run/knock-role <<'ROLE'
#!/bin/sh
case "${SSH_ORIGINAL_COMMAND:-}" in
  status) printf 'Diagnostic role ready\n' ;;
  heartbeat)
    setsid /bin/sh -c 'sleep 120 & wait' </dev/null >/dev/null 2>&1 &
    printf 'Workload %s\n' "$!"
    while :; do printf 'Working\n'; sleep 1; done ;;
  *) exit 1 ;;
esac
ROLE
chmod 0755 /run/knock-role
cat > sshd_config <<'SSHD'
Port 2222
AddressFamily inet
ListenAddress 198.19.0.1
HostKey /run/knock-m1/host
TrustedUserCAKeys /run/knock-m1/ca.pub
AuthorizedPrincipalsFile /run/knock-authority/principals
AuthorizedKeysFile none
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin no
AllowUsers knockprobe
UsePAM no
DisableForwarding yes
PermitTTY no
PermitTunnel no
PermitUserRC no
PermitUserEnvironment no
ForceCommand /bin/sh /run/knock-role
PidFile none
SSHD
/usr/sbin/sshd -t -f sshd_config
GUEST

requester sudo bash -s <<'GUEST'
set -euo pipefail
umask 077
ip link show knockwg >/dev/null 2>&1 && ip link del knockwg
install -d -m 0700 /run/knock-m1
cd /run/knock-m1
test -f wg || wg genkey > wg
wg pubkey < wg > wg.pub
ip link add knockwg type wireguard
ip address add 198.19.0.2/30 dev knockwg
wg set knockwg private-key wg
ip link set knockwg up
GUEST

door_pub=$(door sudo cat /run/knock-m1/wg.pub)
client_pub=$(requester sudo cat /run/knock-m1/wg.pub)
door sudo wg set knockwg peer "$client_pub" allowed-ips 198.19.0.2/32
requester sudo wg set knockwg peer "$door_pub" allowed-ips 198.19.0.1/32 endpoint 198.18.0.1:48001

private=$(mktemp -d "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/knock-probe.XXXXXXXX")
ssh-keygen -q -t ed25519 -N '' -f "$private/client"
door "sudo tee /run/knock-m1/client.pub >/dev/null" < "$private/client.pub"
door "sudo cp /run/knock-m1/client.pub /run/knock-m1/wrong.pub"
door sudo ssh-keygen -q -s /run/knock-m1/ca -I knock-m1 -n knock-fixture -V -1m:+4m /run/knock-m1/client.pub
door sudo ssh-keygen -q -s /run/knock-m1/ca -I knock-m1-wrong -n wrong -V -1m:+4m /run/knock-m1/wrong.pub
door sudo cat /run/knock-m1/client-cert.pub > "$work/client-cert.pub"
door sudo cat /run/knock-m1/wrong-cert.pub > "$work/wrong-cert.pub"
printf '[198.19.0.1]:2222 %s\n' "$(door sudo cat /run/knock-m1/host.pub)" > "$work/protected_hosts"
client_dir=$(requester 'umask 077; mktemp -d /run/user/$(id -u)/knock-ssh.XXXXXXXX')
requester "umask 077; cat > $client_dir/client" < "$private/client"
for file in client-cert.pub wrong-cert.pub protected_hosts; do
  requester "umask 077; cat > $client_dir/$file" < "$work/$file"
done
requester "cp $client_dir/client $client_dir/raw"

door sudo systemd-run --unit=knock-lab-probe --collect --property=RuntimeMaxSec=38s \
  --property=TimeoutStopSec=2s --property=KillMode=control-group --property=LimitCORE=0 \
  /usr/sbin/sshd -D -e -f /run/knock-m1/sshd_config
door "sudo ss -ltnH 'sport = :2222' | grep -q 198.19.0.1"
expect_closed() {
  local client=$1 address=$2
  local status=0
  "$client" "timeout 2 bash -c 'true < /dev/tcp/$address/2222'" >/dev/null 2>&1 || status=$?
  if [[ $status != 1 && $status != 124 ]]; then
    echo "Expected protected TCP port to be unreachable from $client (status $status)" >&2
    exit 1
  fi
}
outsider ping -I knocklab2 -c 1 -W 2 198.18.0.5 >/dev/null
expect_closed requester 198.19.0.1
expect_closed outsider 198.18.0.5
echo 'Protected service unreachable from requester and outsider before admission'

client_command="ssh -o BatchMode=yes -o IdentitiesOnly=yes -o ConnectTimeout=2 -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$client_dir/protected_hosts -p 2222"
door "sudo nft add element inet knock_m1 peers '{ 198.19.0.2 timeout 12s }'"
requester "$client_command -i $client_dir/client knockprobe@198.19.0.1 status"
status=0
requester "$client_command -i $client_dir/raw -o CertificateFile=$client_dir/wrong-cert.pub knockprobe@198.19.0.1 status" > "$work/wrong.log" 2>&1 || status=$?
[[ $status == 255 ]]
grep -q 'Permission denied' "$work/wrong.log"
status=0
requester "$client_command -i $client_dir/raw knockprobe@198.19.0.1 status" > "$work/raw.log" 2>&1 || status=$?
[[ $status == 255 ]]
grep -q 'Permission denied' "$work/raw.log"
echo 'OpenSSH accepted the exact certificate principal and rejected the wrong principal and raw key'
requester "timeout 28 $client_command -i $client_dir/client knockprobe@198.19.0.1 heartbeat" > "$work/heartbeat.log" 2>&1 &
connection=$!
for _ in {1..8}; do
  if grep -q '^Workload [0-9]' "$work/heartbeat.log"; then break; fi
  sleep 1
done
workload=$(awk '/^Workload / {print $2; exit}' "$work/heartbeat.log")
[[ $workload =~ ^[1-9][0-9]*$ ]]
door "test \$(awk -F: '{print \$3}' /proc/$workload/cgroup) = /system.slice/knock-lab-probe.service"
door "sudo wg show knockwg latest-handshakes | awk '\$2 > 0 {found=1} END {exit !found}'"
expired=false
for _ in {1..16}; do
  if door "set -o pipefail; sudo nft list set inet knock_m1 peers | awk '/198[.]19[.]0[.]2/ { found=1 } END { exit found }'"; then
    expired=true
    break
  fi
  sleep 1
done
[[ $expired == true ]]
door sudo systemctl is-active --quiet knock-lab-probe.service
expect_closed requester 198.19.0.1
lines=$(grep -c '^Working$' "$work/heartbeat.log")
sleep 2
[[ $(grep -c '^Working$' "$work/heartbeat.log") == "$lines" ]]
echo 'The kernel timed membership ended new and established traffic while sshd still ran'

wait "$connection" || true
for _ in {1..15}; do
  if door "test ! -e /proc/$workload && test ! -d /sys/fs/cgroup/system.slice/knock-lab-probe.service"; then
    echo 'systemd runtime limit killed the setsid descendant and removed its cgroup'
    expect_closed outsider 198.18.0.5
    exit 0
  fi
  sleep 1
done
echo 'Contained descendant or cgroup remained after runtime expiry' >&2
exit 1
