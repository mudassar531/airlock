import { describe, it, expect, beforeAll } from "vitest";
import { PassThrough } from "node:stream";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";

import {
  startStdioProxy,
  type StdioProxyHandle,
} from "../../src/proxy/stdioProxy.js";
import {
  LineFramer,
  serializeMessage,
  type JsonRpcMessage,
  type JsonRpcRequest,
} from "../../src/proxy/jsonrpc.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

interface ProxyTestbed {
  handle: StdioProxyHandle;
  /** Send a message to the proxy as if from the upstream MCP client. */
  clientSend: (msg: JsonRpcMessage) => void;
  /** Resolves to the next message the proxy delivers back to the client. */
  nextClientMessage: () => Promise<JsonRpcMessage>;
  /** Resolves once `count` messages have arrived from the proxy to the client. */
  collect: (count: number) => Promise<JsonRpcMessage[]>;
  /** Captured stderr text the proxy + child emitted. */
  stderr: () => string;
  shutdown: () => Promise<void>;
}

/**
 * Spawn the proxy with virtual stdio streams so the test driver can act as
 * both the upstream client and the audit-side observer.
 */
function startTestbed(downstreamArgs: string[]): ProxyTestbed {
  const clientStdin = new PassThrough();
  const clientStdout = new PassThrough();
  const clientStderr = new PassThrough();

  const framer = new LineFramer();
  const incoming: JsonRpcMessage[] = [];
  const waiters: ((msg: JsonRpcMessage) => void)[] = [];

  clientStdout.on("data", (chunk: Buffer) => {
    framer.append(chunk);
    while (true) {
      let msg: JsonRpcMessage | null;
      try {
        msg = framer.readMessage();
      } catch {
        continue;
      }
      if (msg === null) return;
      const waiter = waiters.shift();
      if (waiter) waiter(msg);
      else incoming.push(msg);
    }
  });

  let stderrBuf = "";
  clientStderr.on("data", (chunk: Buffer) => {
    stderrBuf += chunk.toString("utf8");
  });

  const handle = startStdioProxy({
    command: downstreamArgs[0]!,
    args: downstreamArgs.slice(1),
    clientStdin,
    clientStdout,
    clientStderr,
  });

  return {
    handle,
    clientSend: (msg) => {
      clientStdin.write(serializeMessage(msg));
    },
    nextClientMessage: () =>
      new Promise<JsonRpcMessage>((resolveOne) => {
        const ready = incoming.shift();
        if (ready) return resolveOne(ready);
        waiters.push(resolveOne);
      }),
    collect: async (count) => {
      const out: JsonRpcMessage[] = [];
      while (out.length < count) {
        // small loop: defer to nextClientMessage which respects backlog
        const m = await new Promise<JsonRpcMessage>((resolveOne) => {
          const ready = incoming.shift();
          if (ready) return resolveOne(ready);
          waiters.push(resolveOne);
        });
        out.push(m);
      }
      return out;
    },
    stderr: () => stderrBuf,
    shutdown: async () => {
      clientStdin.end();
      await handle.shutdown("SIGTERM");
    },
  };
}

let echoServerCmd: string[];
let tmpDir: string;

beforeAll(() => {
  // Compile-free way to run the TS fixture: spawn node with tsx via npx? We
  // don't want that dependency. Simpler: write a pure-JS port of the echo
  // server to a tmp file and run that. Keeps tests self-contained.
  tmpDir = mkdtempSync(resolve(tmpdir(), "airlock-proxy-test-"));
  const serverPath = resolve(tmpDir, "echoServer.cjs");
  const serverJs = `
const { Buffer } = require("node:buffer");

let buf = Buffer.alloc(0);

function readLine() {
  const idx = buf.indexOf(0x0a);
  if (idx === -1) return null;
  const raw = buf.subarray(0, idx);
  buf = buf.subarray(idx + 1);
  if (raw.length > 0 && raw[raw.length - 1] === 0x0d) {
    return raw.subarray(0, raw.length - 1).toString("utf8");
  }
  return raw.toString("utf8");
}

function send(msg) {
  process.stdout.write(JSON.stringify(msg) + "\\n");
}

process.stdin.on("data", (chunk) => {
  buf = buf.length === 0 ? chunk : Buffer.concat([buf, chunk]);
  while (true) {
    const line = readLine();
    if (line === null) return;
    if (line.length === 0) continue;
    let msg;
    try { msg = JSON.parse(line); } catch { continue; }
    if (msg.method === "initialize") {
      send({ jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2024-11-05", capabilities: { tools: {} }, serverInfo: { name: "echo-mock", version: "0.0.1" } } });
    } else if (msg.method === "tools/list") {
      send({ jsonrpc: "2.0", id: msg.id, result: { tools: [{ name: "echo", description: "echo args" }] } });
    } else if (msg.method === "tools/call") {
      send({ jsonrpc: "2.0", id: msg.id, result: { echo: msg.params } });
    } else if (msg.id !== undefined) {
      send({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "unknown method: " + msg.method } });
    }
  }
});

process.stdin.on("end", () => process.exit(0));
`;
  writeFileSync(serverPath, serverJs);
  echoServerCmd = [process.execPath, serverPath];
});

describe("stdioProxy", () => {
  it("round-trips a tools/call byte-faithfully", async () => {
    const tb = startTestbed(echoServerCmd);
    try {
      const call: JsonRpcRequest = {
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: {
          name: "echo",
          arguments: { hello: "world", n: 42, nested: [1, 2, { ok: true }] },
        },
      };
      tb.clientSend(call);
      const response = await tb.nextClientMessage();
      expect(response).toEqual({
        jsonrpc: "2.0",
        id: 1,
        result: { echo: call.params },
      });
    } finally {
      await tb.shutdown();
    }
  });

  it("forwards tools/list verbatim from the downstream server", async () => {
    const tb = startTestbed(echoServerCmd);
    try {
      tb.clientSend({ jsonrpc: "2.0", id: 99, method: "tools/list" });
      const r = await tb.nextClientMessage();
      expect(r).toMatchObject({
        id: 99,
        result: { tools: [{ name: "echo" }] },
      });
    } finally {
      await tb.shutdown();
    }
  });

  it("handles initialize handshake", async () => {
    const tb = startTestbed(echoServerCmd);
    try {
      tb.clientSend({
        jsonrpc: "2.0",
        id: 0,
        method: "initialize",
        params: { protocolVersion: "2024-11-05", capabilities: {} },
      });
      const r = await tb.nextClientMessage();
      expect(r).toMatchObject({
        id: 0,
        result: { serverInfo: { name: "echo-mock" } },
      });
    } finally {
      await tb.shutdown();
    }
  });

  it("preserves order and delivers all 100 messages of a burst", async () => {
    const tb = startTestbed(echoServerCmd);
    try {
      const N = 100;
      for (let i = 0; i < N; i++) {
        tb.clientSend({
          jsonrpc: "2.0",
          id: i,
          method: "tools/call",
          params: { name: "echo", arguments: { i } },
        });
      }
      const responses = await tb.collect(N);
      expect(responses).toHaveLength(N);
      // Order preserved
      for (let i = 0; i < N; i++) {
        expect(responses[i]).toMatchObject({
          id: i,
          result: { echo: { name: "echo", arguments: { i } } },
        });
      }
    } finally {
      await tb.shutdown();
    }
  });

  it("propagates downstream stderr to the configured stderr stream", async () => {
    // Use a tiny node one-liner that emits to stderr and stays alive briefly.
    const tb = startTestbed([
      process.execPath,
      "-e",
      "process.stderr.write('hello-from-child\\n'); setTimeout(()=>process.exit(0), 100);",
    ]);
    await tb.handle.exited;
    expect(tb.stderr()).toContain("hello-from-child");
  });

  it("invokes a custom interceptor for every message", async () => {
    const seen: Array<{ direction: string; method?: string; id?: unknown }> = [];
    const clientStdin = new PassThrough();
    const clientStdout = new PassThrough();
    const clientStderr = new PassThrough();
    const framer = new LineFramer();
    const incoming: JsonRpcMessage[] = [];

    clientStdout.on("data", (chunk: Buffer) => {
      framer.append(chunk);
      while (true) {
        let m: JsonRpcMessage | null;
        try { m = framer.readMessage(); } catch { continue; }
        if (m === null) return;
        incoming.push(m);
      }
    });

    const handle = startStdioProxy({
      command: echoServerCmd[0]!,
      args: echoServerCmd.slice(1),
      clientStdin,
      clientStdout,
      clientStderr,
      interceptor: (msg, ctx) => {
        const entry: any = { direction: ctx.direction };
        if ("method" in msg) entry.method = msg.method;
        if ("id" in msg) entry.id = msg.id;
        seen.push(entry);
        return { forward: msg };
      },
    });

    try {
      clientStdin.write(serializeMessage({
        jsonrpc: "2.0", id: 5, method: "tools/call",
        params: { name: "echo", arguments: { x: 1 } },
      }));
      // Wait for the round-trip
      const start = Date.now();
      while (incoming.length === 0 && Date.now() - start < 5000) {
        await new Promise((r) => setTimeout(r, 10));
      }
      expect(incoming).toHaveLength(1);
      // Should have seen: client->server (the request), server->client (the response)
      const directions = seen.map((s) => s.direction);
      expect(directions).toContain("client-to-server");
      expect(directions).toContain("server-to-client");
    } finally {
      clientStdin.end();
      await handle.shutdown("SIGTERM");
    }
  });
});

// Clean up the temp dir after the whole suite.
import { afterAll } from "vitest";
afterAll(() => {
  try {
    rmSync(tmpDir, { recursive: true, force: true });
  } catch {
    // best effort
  }
});
