# Contributing to Airlock

Thanks for considering a contribution. Airlock is a security tool; the bar is "boring, predictable, inspectable."

## Ground rules

- **Fail closed, not open.** A bug that lets an action through unchecked is worse than a bug that denies a legitimate action. Default to deny / ask when in doubt.
- **Never log raw secrets.** Anything that may carry credentials must pass through `audit/redact.ts` before it touches disk.
- **Determinism.** Given the same call + policy + session state, the verdict must be identical every time. No non-determinism in the policy path.
- **Local-first.** No telemetry. No network calls home. Ever.
- **Keep the policy DSL tiny.** Resist adding knobs. The default policy should remain readable in 30 seconds.

## Setup

```bash
git clone https://github.com/mudassar531/airlock.git
cd airlock
npm install
npm run lint && npm run typecheck && npm test && npm run build
```

Requires Node 20+ (Node 22 is tested in CI too).

## The local loop

```bash
npm run test:watch       # unit tests in watch mode
npm run lint:fix         # eslint with autofix
npm run format           # prettier write
npm run typecheck        # strict tsc check
npm run build            # produce dist/
```

Before opening a PR, run all four (`lint`, `typecheck`, `test`, `build`).

## SPDX headers

Apache-2.0 is the project license. New `.ts` source files should carry the SPDX identifier in a leading comment when convenient:

```ts
// SPDX-License-Identifier: Apache-2.0
```

This is not enforced by lint (yet); add it when touching a file if it's missing.

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/). Examples:

```
feat(proxy): byte-faithful stdio relay
fix(policy): fail closed on unknown action
docs(readme): add trifecta diagram
test(audit): cover hash-chain tamper detection
chore(deps): bump @modelcontextprotocol/sdk to 1.30
```

One focused commit (or a tight series) per logical change.

## Good first issues

Look for issues tagged `good-first-issue`. Common starting points once the project is past v0.1.0:

- Add a tool-name → capability mapping for a popular MCP server.
- Add a new policy rule example to `policy.example.yaml` with a passing test.
- Improve a redaction pattern in `audit/redact.ts` (with a test proving a planted fake secret never appears verbatim).

## Security disclosures

If you find a vulnerability, please **do not** open a public issue. Email the maintainer (TBD in v0.1.0) or open a private security advisory on GitHub.
