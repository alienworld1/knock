#!/usr/bin/env bash
set -euo pipefail
umask 077

if [[ $# != 2 ]]; then
  echo 'Usage: deploy/lab/start.sh UBUNTU_IMAGE NEW_LAB_DIRECTORY' >&2
  exit 2
fi
image=$(realpath -- "$1")
lab=$(realpath -m -- "$2")
expected=04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94
observed=$(sha256sum < "$image")
if [[ ${observed%% *} != "$expected" ]]; then
  echo 'Expected the Ubuntu 24.04 amd64 cloud image dated 2026-10-17.' >&2
  exit 2
fi
if [[ ! -w /dev/kvm ]]; then
  echo 'The lab requires writable /dev/kvm.' >&2
  exit 2
fi
if (( ${#lab} > 75 )); then
  echo 'Use a shorter lab directory for the QEMU sockets.' >&2
  exit 2
fi
mkdir -m 0700 -- "$lab"
ssh-keygen -q -t ed25519 -N '' -f "$lab/admin"
admin_key=$(cat "$lab/admin.pub")

create_guest() {
  local role=$1 host_id=$2 port=$3
  shift 3
  local guest="$lab/$role" memory=1024
  if [[ $role == door ]]; then
    memory=2048
  fi
  local admin_mac="52:54:00:4b:00:$host_id"
  mkdir -- "$guest"
  printf 'instance-id: knock-%s\nlocal-hostname: knock-%s\n' "$role" "$role" > "$guest/meta-data"
  cat > "$guest/user-data" <<CONFIG
#cloud-config
users:
  - name: lab
    groups: sudo
    shell: /bin/bash
    sudo: "ALL=(ALL) NOPASSWD:ALL"
    lock_passwd: true
    ssh_authorized_keys:
      - $admin_key
ssh_pwauth: false
disable_root: true
package_update: true
packages: [nftables, wireguard-tools]
runcmd:
  - [systemctl, mask, sleep.target, suspend.target, hibernate.target, hybrid-sleep.target]
CONFIG
  cat > "$guest/network-config" <<CONFIG
version: 2
ethernets:
  management:
    match: {macaddress: "$admin_mac"}
    dhcp4: true
CONFIG
  local devices=() link number address mac
  for link in "$@"; do
    IFS=, read -r number address mac <<< "$link"
    printf '  link%s:\n    match: {macaddress: "%s"}\n    set-name: knocklab%s\n    addresses: ["%s"]\n' \
      "$number" "$mac" "$number" "$address" >> "$guest/network-config"
    if [[ $role == requester2 ]]; then
      printf '    routes: [{to: 198.18.0.1/32, via: 198.18.0.9}]\n' >> "$guest/network-config"
    fi
    local socket="$lab/link$number.sock"
    local server=off
    [[ $role != door ]] || server=on
    devices+=(-netdev "stream,id=link$number,server=$server,addr.type=unix,addr.path=$socket")
    devices+=(-device "virtio-net-pci,netdev=link$number,mac=$mac")
  done
  xorriso -as mkisofs -quiet -volid cidata -joliet -rock -output "$guest/seed.iso" \
    "$guest/meta-data" "$guest/user-data" "$guest/network-config"
  qemu-img create -q -f qcow2 -F qcow2 -b "$image" "$guest/disk.qcow2" 8G
  qemu-system-x86_64 -accel kvm -cpu host -smp 2 -m "$memory" -display none \
    -name "knock-$role" -daemonize -pidfile "$guest/qemu.pid" \
    -serial "file:$guest/console.log" -monitor "unix:$guest/monitor.sock,server=on,wait=off" \
    -drive "file=$guest/disk.qcow2,if=virtio,format=qcow2" -drive "file=$guest/seed.iso,if=virtio,format=raw,readonly=on" \
    -netdev "user,id=mgmt,hostfwd=tcp:127.0.0.1:$port-:22" -device "virtio-net-pci,netdev=mgmt,mac=$admin_mac" \
    "${devices[@]}"
}

create_guest door 01 29221 1,198.18.0.1/30,52:54:00:4b:01:01 2,198.18.0.5/30,52:54:00:4b:02:01 3,198.18.0.9/30,52:54:00:4b:03:01
create_guest requester 02 29222 1,198.18.0.2/30,52:54:00:4b:01:02
create_guest outsider 03 29223 2,198.18.0.6/30,52:54:00:4b:02:02
create_guest requester2 04 29224 3,198.18.0.10/30,52:54:00:4b:03:02
printf 'Knock lab started in %s\n' "$lab"
