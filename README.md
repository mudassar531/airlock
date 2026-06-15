# Airlock

> A firewall and flight recorder for AI agents — least-privilege approval and a tamper-evident audit log for every action your agent takes.

[![CI](https://github.com/mudassar531/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/mudassar531/airlock/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](https://nodejs.org/)

> ⚠️ **Pre-release.** Airlock is being built phase-by-phase. This README is filled in as features land. See [`BUILD_LOG.md`](BUILD_LOG.md) for the running log.

## The problem

Indirect prompt injection is a structural, unsolved flaw in agentic AI. Any agent that can simultaneously (1) read private data, (2) ingest untrusted external content (web pages, emails, documents, tool outputs), and (3) act on an outbound channel (HTTP, email, payments) is exploitable. This is the **lethal trifecta**, and no clever filter eliminates it.

The agreed mitigation is not detection. It's:

1. **Least privilege** — don't grant the agent capabilities it doesn't need.
2. **Human confirmation** for consequential actions.
3. **Complete audit trails** — every action recorded, tamper-evident.

Airlock is the open-source layer that delivers exactly that, and almost nobody ships a clean one.

## How it works (planned)

```
┌─────────────┐    ┌──────────────────────┐    ┌────────────────────┐
│ MCP Client  │───▶│  airlock wrap proxy  │───▶│ Real MCP server    │
│ (Claude,    │◀───│  • classify          │◀───│ (filesystem, HTTP, │
│ Cursor, VS) │    │  • policy            │    │  shell, ...)       │
│             │    │  • approve           │    │                    │
│             │    │  • audit             │    │                    │
└─────────────┘    └──────────────────────┘    └────────────────────┘
                            │
                            ▼
                   ~/.airlock/audit.log
                   (hash-chained, signed)
```

Airlock spawns your downstream MCP server as a subprocess and relays JSON-RPC traffic between the client and that server. Every `tools/call` is classified (what does this *do*?), checked against a tiny YAML policy, optionally held for one-tap human approval, and recorded to an append-only, hash-chained, ed25519-signed audit log.

## Status

This is being built in seven phases. See [`BUILD_LOG.md`](BUILD_LOG.md) for which phase is live.

- [x] **Phase 0** — Scaffold, CI, repo hygiene
- [ ] **Phase 1** — MCP stdio proxy (pass-through)
- [ ] **Phase 2** — Tamper-evident audit log
- [ ] **Phase 3** — Risk classifier + lethal-trifecta tracker
- [ ] **Phase 4** — Policy engine + default pack
- [ ] **Phase 5** — Approval channels
- [ ] **Phase 6** — Killer demo + Streamable HTTP transport
- [ ] **Phase 7** — Packaging, docs, v0.1.0 release

## Quickstart (coming with Phase 7)

```bash
npx airlock wrap -- npx -y @modelcontextprotocol/server-filesystem /tmp
```

## Development

```bash
git clone https://github.com/mudassar531/airlock.git
cd airlock
npm install
npm run lint && npm run typecheck && npm test && npm run build
node dist/cli.js --version
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the contribution loop.

## Honest limitations

Airlock is **not** a magic prompt-injection detector. It cannot reliably tell a benign tool call from a malicious one purely by inspection. Its value is *structural*: it forces consequential actions through least-privilege defaults, a human approval moment, and a verifiable record. Used as a detector, it will fail. Used as a guardrail, it cuts the trifecta down to size.

## License

[Apache-2.0](LICENSE). This is a security tool — its trust model depends on being inspectable. Read the code.
