---
title: Installation
description: Build knock and knockd from source with the embedded operator console and run project verification checks.
---

Knock ships two Go binaries (`knock` and `knockd`) and a static React operator console embedded directly inside `knock`.

## Build prerequisites

Building from source requires:

- Go `1.26.6`
- Node.js `24` and `pnpm` (`11.x` or `12.x`)
- Foundry (`forge`) targeting Solidity `0.8.28`
- GNU Make and Python 3

:::note
Knock uses `pnpm` for JavaScript workspace dependencies and scripts. Do not use `npm` or `yarn`, and keep the existing lockfile intact.
:::

## Build the binaries

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

Next, follow the [Quickstart](/knock/getting-started/quickstart/) to initialize Diana testnet identities, deploy `KnockRegistry`, and open your first session.
