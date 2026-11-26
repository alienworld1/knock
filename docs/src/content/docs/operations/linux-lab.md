---
title: Linux verification lab
description: Reproducible four-guest QEMU/KVM lab for testing real WireGuard, nftables, OpenSSH, and cgroup containment.
---

Containers share a host kernel and do not prove nftables, WireGuard, or systemd cgroup isolation. Knock ships a reproducible four-guest QEMU/KVM lab under `deploy/lab/` to verify real Linux kernel behavior end to end.

## Prerequisites

- Linux host with writable `/dev/kvm`
- `qemu-system-x86_64`, `qemu-img`, `xorriso`, OpenSSH, and Python 3
- The pinned Ubuntu 24.04 amd64 cloud image dated `2026-10-17` (`SHA-256: 04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`) from [Ubuntu cloud images](https://cloud-images.ubuntu.com/noble/20261017/)

## Guest topology

`deploy/lab/start.sh` creates a disposable `0700` lab directory, generates a temporary `admin` SSH key, disables sleep/suspend targets on each guest, and boots four isolated VMs:

| Guest        | Memory   | Role in verification                                                                                                                                    |
| ------------ | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `door`       | 2048 MiB | Runs `knockd`, WireGuard, `nftables`, per-session `sshd`, and the private HTTP service across isolated point-to-point links (`198.18.0.1`, `.5`, `.9`). |
| `requester`  | 1024 MiB | Primary authorized requester connected to link 1 (`198.18.0.2`).                                                                                        |
| `outsider`   | 1024 MiB | Unauthenticated external machine on link 2 (`198.18.0.6`) verifying pre-admission and post-expiry drops.                                                |
| `requester2` | 1024 MiB | Second independent requester on link 3 (`198.18.0.10`) proving per-session isolation.                                                                   |

## Run the lab probe

Start the guests, run the kernel and SSH containment probe, and shut down cleanly:

```sh
deploy/lab/start.sh noble-server-cloudimg-amd64.img /tmp/knock-lab
deploy/lab/probe.sh /tmp/knock-lab
deploy/lab/stop.sh /tmp/knock-lab
```

Keep the lab directory path under 75 characters so QEMU monitor and stream Unix socket paths fit within Linux `sun_path` limits.

## What probe.sh verifies

1. **Pre-admission isolation:** verifies TCP port `2222` on the Door is unreachable from both `requester` and `outsider` before an nftables timed permit exists.
2. **Certificate and principal enforcement:** verifies OpenSSH accepts the host-signed certificate with the exact expected principal (`knock-fixture`) while rejecting a wrong principal and raw uncertified public key.
3. **Kernel expiry independent of sshd:** starts a long-running workload (`setsid` detached child) inside the session's `systemd-run` unit, confirms the WireGuard handshake succeeds, then waits for the kernel nftables timed set to expire and verifies traffic stops while `sshd` is still running.
4. **Cgroup descendant cleanup:** waits for `RuntimeMaxSec` (`KillMode=control-group`) to terminate the session unit and verifies both the detached `setsid` workload PID and its systemd cgroup directory are completely gone.
