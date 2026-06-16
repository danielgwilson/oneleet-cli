# Contributing

`oneleet-cli` is an unofficial, read-first adapter for Oneleet private web APIs.
Treat endpoint names and response shapes as unstable.

## Local Setup

```bash
npm install
npm run build
npm test
```

Do not commit auth files, cookies, browser captures, raw Oneleet JSON, generated
tenant reports, screenshots, or downloaded evidence.

## Safety Rules

- Keep V1 read-first. Mutations must stay limited to explicit typed workflow
  commands with narrow safety gates; broader write commands need an explicit
  design decision.
- Prefer summarized outputs and aggregate reports.
- Any raw-output path must be visibly unsafe and opt-in.
- Tests must use synthetic fixtures only.
- Default JSON outputs must avoid emails, cookies, URLs, tenant IDs, local paths,
  raw upstream IDs, filenames, and raw evidence text.

## Release Gate

From this package:

```bash
npm run check:release
```

The release gate includes the repo-local secret sweep. You can also run it
directly:

```bash
npm run secret-sweep
```

See [docs/PUBLISHING.md](./docs/PUBLISHING.md) for the full checklist.
