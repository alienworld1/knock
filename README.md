# Knock

Knock grants short-lived, restricted SSH access to verified QoreChain Diana identities. An approver reviews the encrypted request. After approval, the Door opens a private connection and ends it at the fixed deadline or when it observes a finalized Diana revocation.

## Build

Use Go 1.26.6, Foundry, Make, and Python 3. The registry uses Solidity 0.8.28. The checks ran with Foundry commit `be350a64be9178a71a6ff029a72dc4455dcffcb1`.

```sh
make build
make check
```

## Register and inspect a Door

1. Create separate owner, Door, approver, and requester profiles with `bin/knock --profile /path/to/identity.age identity init`. Keep each encrypted profile in a directory with permissions `0700`.
2. Fund the printed addresses with test QOR, then run `bin/knock --profile /path/to/identity.age identity register` for each actor. Registration writes a public recipient card to stdout. [Diana faucet](https://dashboard.qorechain.io/faucet)
3. Run `forge build --root contracts` and deploy with `go run ./contracts/cmd/deploy --profile /path/to/owner.age > network.json`. Keep the resulting registry address and code hash with your trusted configuration.
4. Copy [the example](deploy/door.example.json) to `door.json`. Set the pinned registry, the actor addresses and profiles, and a unique 32-byte Door ID. Generate a Door ID with `openssl rand -hex 32` and prefix it with `0x`. If you configure multiple approvers, sort them by their EVM address bytes.
5. Run `bin/knockd register --config door.json` to commit policy version 1 and publish the signed Card. Run the same command with the next policy version to update it. Run it with the same policy to refresh a Card before its 24-hour expiry.

Give the requester the public Card and registry pin, and confirm the Door account over a trusted channel.

```sh
bin/knock --network network.json --cards cards door trust qor1... --alias validator-ops
bin/knock --network network.json --cards cards door show validator-ops
```

## Request and review access

Start the Mailbox on a loopback address.

```sh
bin/knockd mailbox --state "$HOME/.config/knock/mailbox/mailbox.db"
```

Set `mailbox` and `state` in the Door configuration and republish its signed Card with `knockd register`. Give the requester and approver the updated Card and registry pin. For separate guests, forward the same loopback port to each guest over management SSH. For a remote Mailbox, use an HTTPS reverse proxy and set `--origin` to that HTTPS origin.

Start the Door and prepare the requester VM using the service instructions below. Publish the approver's registered recipient card once. Use separate terminals for the requester and approver. Copy the waiting request ID into `request_id` before running `show` or `approve`.

```sh
bin/knock --profile approver.age --mailbox http://127.0.0.1:8180 identity publish

bin/knock --profile requester.age --network network.json --cards cards \
  validator-ops --ssh --role logs --for 5m --reason -

bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 requests list
bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 requests show "$request_id"
bin/knock --profile approver.age --network network.json --cards cards \
  --mailbox http://127.0.0.1:8180 approve "$request_id"
```

Use `deny` to decline. Keep the requester running while you review. After a grant, Knock opens the restricted SSH menu and shows the fixed expiry in UTC. The `logs` role can read host uptime with `status`. The `maintenance` role can also use `start` to launch one contained diagnostic workload. Use `quit` to leave SSH. The Door ends access and stops the workload at expiry even if the requester or Mailbox has disconnected.

Enter the reason with `--reason -` to keep it out of shell history. The Mailbox can see delivery accounts, timing, sizes, opaque message IDs, and expiry. Reasons are encrypted for approvers. Expired messages are pruned from the live queue. Old disk pages and backups may retain ciphertext.

## Check or revoke a session

Run these commands with your profile, registry and Card options. Copy the session ID from the list. Publish the owner's recipient card before granting access if the owner will check session status.

```sh
knock sessions list --door validator-ops
knock revoke --door validator-ops "$session_id"
knock sessions show --door validator-ops "$session_id"
```

The owner and eligible approvers can revoke. The Door checks Diana directly, even if the Mailbox goes offline. Wait for the Door's signed closure evidence to verify enforcement. During a Diana outage, the Door requires fresh verification for new grants and existing grants still expire locally. If status becomes stale, Knock shows the last verified observation. When cleanup is incomplete, the Door retains its ownership record and retries.

## Run an SSH Door

Use a dedicated, always-on Ubuntu 24.04 VM with cgroup v2, WireGuard, nftables, and OpenSSH. Keep time synchronized and disable suspend. Keep management SSH on a separate network. Knock reserves the `knockdoor` interface, the `knock_ssh` nftables table, `198.19.0.0/28`, and SSH ports 2222–2229 on `198.19.0.1`. Each concurrent session needs its own local account. The setup below creates two slots. For up to eight, add `knockssh2` through `knockssh7` with the same restrictions.

Set `wireGuardEndpoint` in the private Door configuration to a numeric address and UDP port reachable by the requester, for example `198.18.0.1:48001` in the lab. Permit that UDP port on the Door's external interface. Leave the private SSH listener behind Knock's firewall. Install the files under `/etc/knock` with root ownership and the Door profile at mode `0600`. Keep the owner profile on the operator machine.

```sh
sudo install -m 0755 bin/knockd /usr/local/bin/knockd
sudo useradd --system --no-create-home --home-dir / --shell /bin/sh --password NP knockssh
sudo useradd --system --no-create-home --home-dir / --shell /bin/sh --password NP knockssh1
sudo install -d -m 0755 /run/sshd /etc/systemd/system/knockd.service.d
systemd-ask-password 'Door passphrase' |
  sudo systemd-creds encrypt --name=door-passphrase --with-key=host - /etc/knock/door.cred
sudo install -m 0644 deploy/systemd/knockd.service /etc/systemd/system/knockd.service
sudo install -m 0644 deploy/systemd/10-ssh.conf /etc/systemd/system/knockd.service.d/10-ssh.conf
sudo systemctl daemon-reload
sudo systemctl start knockd
```

On the requester VM, install `bin/knock` at `/usr/local/bin/knock` as root, plus WireGuard tools and OpenSSH. In a regular Linux login session, grant the requester's local group the two tunnel commands in [the sudoers example](deploy/knock-tunnel.sudoers). Install it with `sudo visudo -f /etc/sudoers.d/knock-tunnel`. The SSH client runs as the requester.

The requester holds its one-time keys in memory and uses private tmpfs files for OpenSSH. Knock removes these files and the temporary tunnel on exit and cleans up leftovers before the next SSH connection. Key disposal is best-effort. The Door verifies cleanup of outstanding sessions on restart. With the Door stopped, run `sudo knockd reconcile --config /etc/knock/door.json` to retry host cleanup manually.

The host credential key and the encrypted credential require storage protection against full disk access. Registry and key verification use trusted Diana endpoints. QoreSeal is a draft pending external review. [QoreSeal documentation](https://docs.qorechain.io/developer-tools/qoreseal/)

## Check the Linux lab

Use a host with KVM, QEMU, xorriso, OpenSSH, and Python 3. Download the Ubuntu 24.04 amd64 image dated 2026-10-17. Verify the signed Ubuntu manifest. The lab script checks the pinned image checksum and opens management SSH ports on loopback. [Ubuntu cloud images](https://cloud-images.ubuntu.com/noble/20261017/)

```sh
deploy/lab/start.sh noble-server-cloudimg-amd64.img /tmp/knock-lab
deploy/lab/probe.sh /tmp/knock-lab
deploy/lab/stop.sh /tmp/knock-lab
```

The lab includes two requester guests and a separate outsider. The probe uses the Door, first requester, and outsider to check the closed service, WireGuard, SSH certificate restrictions, timed nftables membership, and systemd cgroup cleanup. Use a new lab directory for a clean run.

Verified on Diana with registry `0x1c334C21920CD88fB9E372Acd78a1772D2A32a78`. [Deployment](https://explore.qore.network/tx/0x0719fc5668e0c2772d800a322df5ec96a51dc323627c6ccbd8a48f89207b53cb), [Door registration](https://explore.qore.network/tx/0x2766c0a4e8111703bb8f8927b8fd51fac87ca8e55099a22caa1b751ca8dbf97d), [policy update](https://explore.qore.network/tx/0xdfa0f058aaa11a72cead637c982b84600d8a940b593b2494ffa8aba8f5e96a85), [Live SSH revocation](https://explore.qore.network/tx/0x5eab80cb03111cbe8bf9322ba39ee4ecc675326bb73fc01e3b67b3631a13f965). In the lab, the revoked connection ended about 25 seconds after the command started while the Mailbox was offline.

Apache-2.0.
