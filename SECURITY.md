# Security Policy

This project is an unofficial private-surface adapter. It stores a Oneleet web
session cookie locally when CDP auth import is used.

## Supported Versions

Only the current `0.x` line is supported.

## Reporting A Vulnerability

Open a private advisory or contact the maintainer before filing a public issue
if the report includes:

- leaked cookies or auth material
- tenant identifiers or tenant data
- raw Oneleet API payloads
- browser captures, HARs, traces, storage state, screenshots, or evidence files

## Secret Handling

The CLI never accepts session cookies as command-line flags. Use either:

- `ONELEET_APP_COOKIE` and `ONELEET_TENANT_ID` environment variables for
  ephemeral runs
- `oneleet auth import-cdp --port 9333` for local config at
  `~/.config/oneleet/config.json`

`ONELEET_API_BASE_URL` must point at a Oneleet HTTPS host by default. The
`ONELEET_ALLOW_UNSAFE_API_BASE_URL=1` override is only for synthetic local tests.

Run `npm run check:release` before publishing or sharing artifacts.
