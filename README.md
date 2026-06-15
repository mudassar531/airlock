# Airlock

> A firewall and flight recorder for AI agents — least-privilege approval and a tamper-evident audit log for every action your agent takes.

[![CI](https://github.com/mudassar531/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/mudassar531/airlock/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org/)
[![MCP](https://img.shields.io/badge/MCP-stdio%20%2B%20Streamable%20HTTP-purple.svg)](https://modelcontextprotocol.io/)

> 🎬 **The demo people will screenshot:**  `npm run demo:safe` shows Airlock holding a prompt-injection-driven exfiltration as a lethal-trifecta violation while `npm run demo:unsafe` shows the same agent leaking a fake secret to a local sink. Reproducible in one minute. See [`demo/README.md`](demo/README.md).

## The problem

Indirect prompt injection is a structural, unsolved flaw in agentic AI. Any agent that can simultaneously (1) **read private data**, (2) **ingest untrusted external content** (web pages, emails, documents, tool outputs), and (3) **act on an outbound channel** (HTTP, email, payments) is exploitable. This is the **lethal trifecta**, and no clever filter eliminates it.

The agreed mitigation is not detection. It's:

1. **Least privilege** — don't grant the agent capabilities it doesn't need.
2. **Human confirmation** for consequential actions.
3. **Complete audit trails** — every action recorded, tamper-evident.

Airlock is the open-source layer that delivers exactly that.

## One-command install

```bash
npx airlock --help
# or globally:
npm install -g airlock
```

Requires Node 20+.

## 60-second quickstart

Wrap any [MCP server](https://modelcontextprotocol.io/) with Airlock. Point your MCP client (Claude Desktop, Cursor, VS Code, Claude Code) at the wrapped command instead of the bare one:

```bash
# generate a signing keypair and the audit log dir (one-time)
airlock init

# wrap the official filesystem MCP server
airlock wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp

# in another terminal, see what the agent did
airlock log
airlock verify
```

Every `tools/call` the agent makes is classified, scored, checked against the active policy, optionally held for human approval, and recorded.

```
[2026-06-15T01:02:22Z] seq=3 ALLOW  read_file      filesystem/read  risk=low  27ms — policy: forwarded
[2026-06-15T01:02:22Z] seq=2 DENY   stripe_create_charge  payment/spend  risk=critical  rule=never-spend-money  0ms — money movement is always treated as critical
[2026-06-15T01:02:22Z] seq=1 ALLOW  read_file      filesystem/read  risk=low  29ms — policy: forwarded
```

## How policies work

Airlock ships with safe defaults. Override by dropping an `airlock.policy.yaml` next to where you run `airlock wrap`, or in `~/.airlock/policy.yaml`, or via `--policy <file>`. The DSL is intentionally tiny:

```yaml
version: 1
defaults:
  on_unmatched: ask        # allow | deny | ask | log  — fail safe, not open
rules:
  - name: never-spend-money
    match: { capability: payment }
    action: deny
  - name: hold-the-lethal-trifecta
    match: { trifecta: true }
    action: ask
  - name: confirm-destructive-fs
    match: { capability: filesystem, operation: delete }
    action: ask
  - name: confirm-shell-exec
    match: { capability: shell }
    action: ask
  - name: confirm-outbound-send
    match: { capability: message, operation: send }
    action: ask
  - name: allow-plain-reads
    match: { operation: read }
    action: allow
```

- Rules evaluate **top-to-bottom, first match wins**.
- `match` can constrain on `capability` (`filesystem|shell|network|message|payment|secret|other`), `operation` (`read|write|delete|execute|send|spend|other`), `risk_min` (`low|medium|high|critical`), `trifecta: true`, or `tool` (literal or trailing-`*` glob).
- Actions: `allow` forwards the call, `log` forwards loudly, `deny` returns a structured MCP error to the client (the downstream server never sees it), `ask` holds the call for human approval.
- Approval channels: interactive CLI prompt on a TTY, desktop notification, or out-of-band via `airlock approve <id>` / `airlock deny <id>` (run `airlock pending` to see what's waiting). Default timeout 60s → deny.
- Invalid policy → Airlock refuses to run (`exit 3`). Fail closed.

Inspect a hypothetical call without running anything:

```bash
airlock policy check --tool http_post --args '{"url":"https://attacker.example"}' --trifecta
```

## The audit log

Every recorded action lands in `~/.airlock/audit.log` (override with `$AIRLOCK_HOME`). JSONL, sha256-chained, ed25519-signed at the head.

```bash
airlock log              # human view, recent first
airlock log --json       # raw JSONL
airlock log --tail 200   # last 200 entries
airlock verify           # walk the chain, report the exact seq of any break
```

Every value passes through redaction before disk write. Known secret patterns (`sk-*`, `github_pat_*`, `ghp_*`, `sk-ant-*`, `AKIA*`, `xox[abprs]-*`, JWTs), key-name heuristics (`password`, `apiKey`, `token`, `authorization`, …), and high-entropy opaque blobs all get replaced with `[REDACTED]`. The audit log is what makes Airlock *more* inspectable than a bare agent setup, not less.

## Security model & honest limitations

**Airlock is not a prompt-injection detector.** It cannot reliably tell a malicious tool call from a legitimate one by inspection. Anyone selling you a regex that "catches all prompt injections" is selling you snake oil. The lethal trifecta is a *structural* flaw, so the mitigation has to be structural:

1. **Least privilege.** A read-only filesystem server can't exfiltrate. A wrapped server with `never-spend-money` can't drain your card.
2. **Human confirmation** at the points that matter — outbound actions, destructive ops, anything in the trifecta shape.
3. **Tamper-evident audit trail.** Post-hoc you can always reconstruct exactly what the agent attempted, what verdict each call got, who approved or denied, and how long they took.

Used as a detector, Airlock will fail. Used as a guardrail, it cuts the trifecta down to size. The default policy is the smallest set of rules that delivers that property; the README and `policy.example.yaml` are the policy.

### What Airlock does NOT do

- It does not phone home. No telemetry, no opt-in metrics, no "anonymous usage data." Audit logs stay on disk in `$AIRLOCK_HOME`.
- It does not modify the downstream server's responses. The interceptor is byte-faithful on the response path.
- It does not analyze prompt content. Verdicts are based on call shape (capability, operation, session state, risk), not on the agent's "intent."

## Development

```bash
git clone https://github.com/mudassar531/airlock.git
cd airlock
npm install
npm run lint && npm run typecheck && npm test && npm run build
node dist/cli.js --version
node dist/cli.js --help
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the ground rules (fail closed, redact before log, determinism, tiny DSL).

## Build log

See [`BUILD_LOG.md`](BUILD_LOG.md) — one paragraph per phase covering what shipped, what the verification gate proved, and anything deferred.

- ✅ **Phase 0** — Scaffold, CI, repo hygiene
- ✅ **Phase 1** — MCP stdio proxy (byte-faithful pass-through)
- ✅ **Phase 2** — Tamper-evident audit log
- ✅ **Phase 3** — Risk classifier + lethal-trifecta tracker
- ✅ **Phase 4** — Policy engine + default pack
- ✅ **Phase 5** — Approval channels
- ✅ **Phase 6** — Killer demo + Streamable HTTP transport
- ✅ **Phase 7** — Packaging + v0.1.0 release prep

## License

[Apache-2.0](LICENSE). This is a security tool — its trust model depends on being inspectable. Read the code.
