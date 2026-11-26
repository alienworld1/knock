---
title: Host setup
description: Provision a dedicated Ubuntu 24.04 Linux Door host with systemd encrypted credentials, slot accounts, and requester sudoers rules.
---

Run each Knock Door on a dedicated Ubuntu 24.04 LTS x86-64 host (2 GiB RAM, cgroup v2, kernel WireGuard, `nftables`, time sync enabled, suspend disabled) with operator management SSH on a separate interface.

## Reserved host resources

`knockd` owns a small isolated network slice and firewall table so Knock teardown never interferes with unrelated system rules:

- WireGuard interface: `knockdoor`
- nftables table: `inet knock_ssh`
- Protected subnet: `198.19.0.0/28` (Door address `198.19.0.1`)
- Per-session OpenSSH listeners: TCP ports `2222` to `2229` bound to `198.19.0.1`
- Runtime tmpfs state: `/run/knock-ssh`

Allow inbound UDP on the configured `wireGuardEndpoint` port through your external interface firewall, and block public access to ports `2222` to `2229`.

## Create non-root SSH slot accounts

For an Approval Door, install OpenSSH and create pre-provisioned non-root slot accounts with password login disabled (`NP` leaves the account locked for password auth while allowing certificate auth):

```sh
sudo useradd --system --no-create-home --home-dir / --shell /bin/sh --password NP knockssh
sudo useradd --system --no-create-home --home-dir / --shell /bin/sh --password NP knockssh1
sudo install -d -m 0755 /run/sshd
```

## Install knockd and systemd units

Keep `/etc/knock` (`0700`) and the Door profile (`0600`) root-owned, and keep the `ownerProfile` off the Door host entirely.

Encrypt the Door passphrase with systemd host-bound credentials and install the shipped unit and drop-in (`deploy/systemd/knockd.service` and `deploy/systemd/10-ssh.conf`):

```sh
sudo install -m 0755 bin/knockd /usr/local/bin/knockd
sudo install -d -m 0700 /etc/knock
sudo install -d -m 0755 /etc/systemd/system/knockd.service.d
systemd-ask-password 'Door passphrase' |
  sudo systemd-creds encrypt --name=door-passphrase --with-key=host - /etc/knock/door.cred
sudo install -m 0644 deploy/systemd/knockd.service /etc/systemd/system/knockd.service
sudo install -m 0644 deploy/systemd/10-ssh.conf /etc/systemd/system/knockd.service.d/10-ssh.conf
sudo systemctl daemon-reload
sudo systemctl start knockd
```

The `10-ssh.conf` drop-in runs `knockd` as `root` because managing `knockdoor`, `inet knock_ssh`, `/run/knock-ssh`, and transient `systemd-run` session slices requires kernel and systemd privilege.

## Requester Linux setup

On the requester Linux machine, install `bin/knock` to `/usr/local/bin/knock`, install `wireguard-tools` and OpenSSH, and add the scoped sudoers rule from `deploy/knock-tunnel.sudoers` (replacing `knockclient` with your requester group):

```sh
sudo visudo -f /etc/sudoers.d/knock-tunnel
```

```txt
%knockclient ALL=(root) NOPASSWD: /usr/local/bin/knock ^tunnel-(up|down)\ kc[0-9a-f]{12}$
```

This permits `knock` to bring up and tear down its temporary `kc...` WireGuard interface without granting general root privileges.

## Manual host reconciliation

If a Door host stops abruptly or requires manual verification before restarting `knockd`, inspect and clean up any leftover Knock peers, permits, or session units:

```sh
sudo knockd reconcile --config /etc/knock/door.json
```
