---
title: knock CLI
description: Command, flag, output, and exit code reference for the knock client binary.
---

`knock` is the terminal utility for requesters, approvers, Door owners, and auditors. It performs local key decryption, Diana identity checks, QoreSeal encryption, WireGuard and SSH setup, and local console hosting.

## Global flags

Every subcommand accepts these persistent flags:

| Flag                 | Purpose                                                                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--profile <path>`   | Path to the passphrase-encrypted `.age` identity profile. Defaults to `$XDG_CONFIG_HOME/knock/identity.age` (or `~/.config/knock/identity.age`).   |
| `--network <path>`   | Path to `network.json` containing the pinned `KnockRegistry` address and code hash. Defaults to `network.json` inside your Knock config directory. |
| `--cards <dir>`      | Directory containing signed `.card` Door Card files. Defaults to `cards/` inside your Knock config directory.                                      |
| `--mailbox <origin>` | Mailbox HTTP/HTTPS origin for operator and identity commands.                                                                                      |

## Requesting access

### Approval Door (SSH)

```sh
knock <door> --ssh --role <role> --for <duration> --reason -
```

- `<door>`: trusted local alias (from `knock door trust`) or `qor1...` Door account address.
- `--ssh`: request a scoped SSH session.
- `--role <role>`: role advertised by the Door (`logs` or `maintenance`).
- `--for <duration>`: requested duration in Go duration syntax (whole seconds, e.g. `15m`, `300s`). Must be within policy `maxDurationSeconds`.
- `--reason <text>`: short explanation for approvers (up to 512 printable bytes). Pass `-` to enter the reason privately from the terminal prompt without putting it in shell history.

### Metered Door (private service tunnel)

```sh
knock <door> --tunnel --pay <duration> [--price-uqor <amount>]
```

- `--tunnel`: connect to a metered private service over WireGuard.
- `--pay <duration>`: exact fixed pass duration offered by the Door (whole seconds, e.g. `2m`).
- `--price-uqor <amount>`: optional expected integer price in `uqor` (`1 test QOR = 1,000,000 uqor`). Required when running without an interactive terminal; causes exit `5` if the on-chain offer price differs.

## Identity commands

```sh
knock identity init
knock identity register
knock identity publish --mailbox <origin>
```

- `identity init`: creates a new `0700` profile directory and encrypted `0600` `.age` identity file, printing your `qor1...` address.
- `identity register`: registers your hybrid ML-DSA-87 signing key and ML-KEM-1024 encryption key on QoreChain Diana after funding.
- `identity publish`: signs and uploads your recipient card to the Mailbox so Door owners or requesters can look it up.

## Door commands

```sh
knock door trust <account> --alias <name>
knock door show <door> [--json] [--revocation <session-id>]
```

- `door trust`: verifies the Door Card on Diana and binds `<account>` to `<name>` (`a-z`, `0-9`, `-`). If the Door's signing key ever changes, future lookups refuse to continue silently until re-verified.
- `door show`: prints verified policy details, status (`Approval required`, `Purchase required`, or `Disabled`), roles or offer terms, and registry reference. Pass `--revocation <hex>` to query whether a 32-byte session reference is revoked on `KnockRegistry`.

## Operator review, approval, and revocation

```sh
knock requests list [--json]
knock requests show <request-id> [--json]
knock approve <request-id> [--yes]
knock deny <request-id> [--yes]
knock sessions list --door <door> [--json]
knock sessions show --door <door> <session-id> [--json]
knock revoke --door <door> <session-id>
```

- `requests list` / `show`: decrypts verified incoming approval requests using your local profile. `--json` intentionally omits the private `--reason` field.
- `approve` / `deny`: seals a signed Entry Pass (or denial) for the exact reviewed request. Prompts for `yes` unless `--yes` is passed after reviewing `<request-id>`.
- `sessions list` / `show`: reads signed host status records for active and closed sessions, checking Diana freshness and reporting `Chain monitoring` health.
- `revoke`: submits a PQ-authenticated revocation transaction to `KnockRegistry` on Diana as the Door owner or an authorized approver.

## Operator console, payments, and audit

```sh
knock console
knock payment show <pass-reference> [--json]
knock audit rotate --door <door> --epoch <n> [--member qor1...,qor1... | --clear]
knock history list --door <door> [--json]
knock history show --door <door> [--from <file>] [--json] <receipt-id>
```

- `console`: starts the local loopback web interface after unlocking your profile.
- `payment show`: inspects a recorded pass reference across local records, Diana transactions, `KnockRegistry` state, and Door fulfillment status.
- `audit rotate`: sent by the Door owner to establish or rotate the QoreSeal audit group epoch (`--epoch 0` for initial setup, or `--clear` to pause receipts).
- `history list` / `show`: decrypts verified Receipts from the Mailbox or from an offline `knockd audit-export` file (`--from`).

## Output conventions and exit codes

- Progress messages and errors print to `stderr`; results and `--json` payloads print to `stdout` so pipes remain clean.
- Respects `NO_COLOR` and non-TTY output automatically without escape codes or interactive prompts.
- Pass `--price-uqor` on metered passes and `--yes` on decisions when automating after review.

| Exit code | Meaning                                                                                               |
| --------- | ----------------------------------------------------------------------------------------------------- |
| `0`       | Command succeeded.                                                                                    |
| `2`       | Invalid arguments, flags, local configuration, or canceled confirmation.                              |
| `3`       | Identity, Door Card, policy, or QoreChain verification failure.                                       |
| `4`       | Request denied by approver or expired before grant issuance.                                          |
| `5`       | Metered offer price mismatch (`--price-uqor`), reverted purchase, or uncertain transaction broadcast. |
| `6`       | WireGuard tunnel, SSH connection, or host provisioning failure.                                       |
| `7`       | Host teardown failed or `Cleanup incomplete`.                                                         |
| `8`       | Local profile unlock, filesystem, Mailbox I/O, or status read error.                                  |
