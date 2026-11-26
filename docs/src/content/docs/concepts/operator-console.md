---
title: Operator console
description: Local-first web interface for reviewing requests, monitoring active deadlines, revoking sessions, and reading audit history.
---

The operator console is a lightweight browser workspace embedded inside `knock`. It is designed for local review and inspection alongside the CLI.

## Local-first security model

```sh
knock --profile approver.age --network network.json --cards cards console
```

- You unlock your `.age` identity profile in the terminal before the HTTP server starts.
- `knock console` binds strictly to `127.0.0.1` on an ephemeral port and prints a one-time URL carrying a bootstrap token. Opening it sets an `HttpOnly`, `SameSite=Strict`, `Path=/` session cookie and cleans the token from the browser history.
- Private keys, decryption, and QoreChain signatures stay inside the local Go process. Browser actions call loopback endpoints over the authenticated local session.
- Press `Ctrl+C` in the terminal when finished. The CLI works independently while the console is stopped.

## Three views

The console has no analytics dashboards, token price tickers, or remote account settings. Navigation has three views:

1. **Doors.** Select a trusted Door, inspect its verified Door Card and Door Policy, and review incoming pending requests with locally decrypted reasons. Grant or deny an exact request through a confirmation dialog.
2. **Sessions.** Inspect active and recently closed sessions. Active sessions show the horizontal brass **Access duration** rail, tabular remaining time, absolute UTC/local expiry, scope, and chain monitoring health. Authorized operators can trigger an on-chain **Revoke** and track progress honestly through `Revocation pending` to `Revocation enforced`.
3. **History.** For Doors with audit history enabled, decrypt verified session Receipts locally for authorized epochs, check signature verification and cleanup outcomes, and let the Door owner request audit membership rotation.

## Theme and accessibility

- Dark mode is the first-run default, matching the console's olive and brass instrument palette.
- Choose **Dark**, **Light**, or **System** in the navigation footer; the preference persists locally.
- Every workflow supports full keyboard navigation, visible focus rings, screen-reader status announcements, 200% zoom, and narrow viewports down to 320 px.
- Countdown timers update numerically without repeating screen-reader announcements every second.
