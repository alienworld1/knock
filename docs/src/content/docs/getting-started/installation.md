---
title: Installation
description: Install the Linux x86-64 binaries or build Knock from source.
---

## Download for Linux x86-64

The release archive includes `knock`, `knockd`, the embedded operator console, and the Door setup files. You can run the binaries without Go, Node.js, or Foundry.

Download [knock-linux-amd64.tar.gz](/knock/downloads/knock-linux-amd64.tar.gz) and its [SHA-256 checksum](/knock/downloads/SHA256SUMS). The same files are available on [GitHub Releases](https://github.com/alienworld1/knock/releases/latest) for anyone with repository access.

In the download directory, verify and extract the archive:

```sh
sha256sum -c SHA256SUMS &&
  tar -xzf knock-linux-amd64.tar.gz &&
  cd knock-linux-amd64 &&
  bin/knock --help &&
  bin/knockd --help
```

Follow the [Quickstart](/knock/getting-started/quickstart/) from the extracted directory, and check the runtime packages below for each machine.

## Build from source

Building from source requires:

- Go `1.26.6`
- Node.js `24` and `pnpm` (`11.x` or `12.x`)
- Foundry (`forge`) targeting Solidity `0.8.28`
- GNU Make and Python 3

:::note
Knock uses `pnpm` for JavaScript workspace dependencies and scripts. Do not use `npm` or `yarn`, and keep the existing lockfile intact.
:::

Install console dependencies, compile the static operator console, and build `bin/knock` and `bin/knockd`:

```sh
pnpm --dir web/console install --frozen-lockfile
make build
```

`make build` builds the Vite bundle into `cmd/knock/consoleassets/dist` and embeds it into `bin/knock`. You do not need Node.js on the machines that run `knock` or `knockd`.

## Run the full check suite

To verify Go, TypeScript, accessibility tests, and Solidity contracts together:

```sh
pnpm --dir web/console exec playwright install chromium
make check
```

`make check` runs:

1. `make build` (`tsc`, `vite build`, and Go binaries `bin/knock` and `bin/knockd`).
2. `pnpm --dir web/console format:check`, Vitest unit tests, and Playwright WCAG AA accessibility checks.
3. `go vet ./...` and `go test ./...`.
4. `forge fmt --check --root contracts`, Foundry unit and fuzz tests (`forge test --root contracts`), and ABI parity verification against `internal/chain/registry.abi.json`.

## Target runtime requirements

| Machine                           | Platform and packages                                                                                                                                                                 |
| --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Door host (`knockd`)**          | Ubuntu 24.04 LTS x86-64, 2 GiB RAM, systemd with cgroup v2, kernel WireGuard, `wireguard-tools`, `nftables`, OpenSSH (`sshd`, `ssh-keygen`), NTP time sync enabled, suspend disabled. |
| **Requester machine (`knock`)**   | Linux with `wireguard-tools`, OpenSSH (`ssh`), and a limited `sudoers` rule if using `--tunnel` or `--ssh` WireGuard setup.                                                           |
| **Approver or auditor (`knock`)** | Linux terminal for CLI commands and optional local loopback browser for `knock console`.                                                                                              |
