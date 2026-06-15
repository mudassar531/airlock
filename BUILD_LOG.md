# BUILD_LOG

A running, append-only log of what shipped in each phase, what the verification gate proved, and anything deferred. One paragraph per phase.

---

<!-- entries appended below as phases land -->

## Phase 0 — Scaffold, CI, repo hygiene (✅ shipped)

Bootstrapped a strict ESM TypeScript project on Node 20+: `commander` CLI shell exposing `--version` and `--help`, `tsup` bundler that emits a shebang-prefixed `dist/cli.js`, `vitest` test runner with one smoke test on `constants.ts`, ESLint v9 flat config + Prettier, GitHub Actions CI matrix on Node 20 and 22 running lint → typecheck → test → build → CLI smoke. Apache-2.0 LICENSE with copyright notice, README problem statement + phase tracker, CONTRIBUTING with fail-closed / no-telemetry ground rules, BUILD_LOG. The verification gate ran clean locally: `lint && typecheck && test && build` all pass and `node dist/cli.js --version` prints `0.1.0`. Nothing deferred.

## Phase 1 — MCP stdio proxy (✅ shipped)

`airlock wrap -- <command...>` now spawns the downstream MCP server as a child process and relays newline-delimited JSON-RPC bidirectionally with byte-faithful framing. The proxy has three pieces: `src/proxy/jsonrpc.ts` (a `LineFramer` that buffers stdin into discrete messages with CRLF + UTF-8-chunk-boundary tolerance, plus typed JSON-RPC interfaces and type guards), `src/proxy/interceptor.ts` (the single hook every later phase extends — `(msg, ctx) => { forward, respondToClient? }`, identity in this phase), and `src/proxy/stdioProxy.ts` (spawns the child, runs serial per-direction write queues so messages never interleave at the byte level, drains complete frames in order so JSON-RPC ordering survives back-to-back chunks, and passes child stderr through unchanged for diagnostics). Verified the SDK wire format against `@modelcontextprotocol/sdk@1.29.0 shared/stdio.ts` before coding — one JSON object per line, terminated by `\n`. Gate ran clean: 12 framer unit tests (chunk-boundary, CRLF, UTF-8 multibyte, 100-message burst), 6 proxy integration tests against a spawned echo fixture (round-trip equality, `tools/list`/`initialize`/`tools/call`, 100 in-order responses, stderr passthrough, interceptor seam fires for both directions), plus an end-to-end smoke driving the built bin through 101 sequential calls with order preserved.
