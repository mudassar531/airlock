import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { PassThrough } from "node:stream";
import { writeFileSync } from "node:fs";

import { createAuditingInterceptor, AIRLOCK_DENIED_CODE } from "../../src/audit/interceptor.js";
import { AuditLog } from "../../src/audit/log.js";
import { airlockPaths } from "../../src/config.js";
import { ApprovalQueue } from "../../src/approval/queue.js";
import { DEFAULT_POLICY } from "../../src/policy/defaults.js";
import { LineFramer, serializeMessage, type JsonRpcMessage } from "../../src/proxy/jsonrpc.js";
import { startStdioProxy } from "../../src/proxy/stdioProxy.js";

let tmp: string;
let originalHome: string | undefined;
let echoServerPath: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), "airlock-ask-"));
  originalHome = process.env.AIRLOCK_HOME;
  process.env.AIRLOCK_HOME = tmp;
  echoServerPath = resolve(tmp, "echo.cjs");
  writeFileSync(
    echoServerPath,
    `
let buf = Buffer.alloc(0);
function readLine(){const i=buf.indexOf(0x0a);if(i===-1)return null;const r=buf.subarray(0,i);buf=buf.subarray(i+1);if(r.length&&r[r.length-1]===0x0d)return r.subarray(0,r.length-1).toString();return r.toString();}
function send(m){process.stdout.write(JSON.stringify(m)+"\\n");}
process.stdin.on("data",(c)=>{buf=buf.length?Buffer.concat([buf,c]):c;while(true){const l=readLine();if(l===null)return;if(!l)continue;let m;try{m=JSON.parse(l);}catch{continue;}if(m.method==="tools/call")send({jsonrpc:"2.0",id:m.id,result:{echo:m.params}});else if(m.id!==undefined)send({jsonrpc:"2.0",id:m.id,error:{code:-32601,message:"unknown"}});}});
process.stdin.on("end",()=>process.exit(0));
`,
  );
});

afterEach(() => {
  if (originalHome === undefined) delete process.env.AIRLOCK_HOME;
  else process.env.AIRLOCK_HOME = originalHome;
  rmSync(tmp, { recursive: true, force: true });
});

interface Testbed {
  send: (msg: JsonRpcMessage) => void;
  responses: JsonRpcMessage[];
  nextResponse: () => Promise<JsonRpcMessage>;
  shutdown: () => Promise<void>;
}

function startTestbed(approvals: ApprovalQueue): Testbed {
  const clientStdin = new PassThrough();
  const clientStdout = new PassThrough();
  const clientStderr = new PassThrough();
  const framer = new LineFramer();
  const responses: JsonRpcMessage[] = [];
  const waiters: ((m: JsonRpcMessage) => void)[] = [];
  clientStdout.on("data", (chunk: Buffer) => {
    framer.append(chunk);
    while (true) {
      let m: JsonRpcMessage | null;
      try {
        m = framer.readMessage();
      } catch {
        continue;
      }
      if (m === null) return;
      const w = waiters.shift();
      if (w) w(m);
      else responses.push(m);
    }
  });

  const auditLog = new AuditLog(airlockPaths(tmp));
  const handle = startStdioProxy({
    command: process.execPath,
    args: [echoServerPath],
    clientStdin,
    clientStdout,
    clientStderr,
    interceptor: createAuditingInterceptor({
      log: auditLog,
      policy: DEFAULT_POLICY,
      approvals,
    }),
  });

  return {
    send: (m) => clientStdin.write(serializeMessage(m)),
    responses,
    nextResponse: () =>
      new Promise<JsonRpcMessage>((res) => {
        const ready = responses.shift();
        if (ready) return res(ready);
        waiters.push(res);
      }),
    shutdown: async () => {
      clientStdin.end();
      await handle.shutdown("SIGTERM");
    },
  };
}

describe("ask path: approve -> forward", () => {
  it("a shell_exec call held for approval is forwarded once approved", async () => {
    const queue = new ApprovalQueue({ timeoutMs: 5_000, pendingDir: resolve(tmp, "pending") });
    const tb = startTestbed(queue);
    try {
      tb.send({
        jsonrpc: "2.0",
        id: 1,
        method: "tools/call",
        params: { name: "shell_exec", arguments: { cmd: "ls" } },
      });
      // Wait for the queue to receive the approval, then approve it.
      await new Promise<void>((res) => {
        const t = setInterval(() => {
          if (queue.size === 1) {
            clearInterval(t);
            res();
          }
        }, 5);
      });
      const id = queue.list()[0]!.id;
      queue.resolve(id, "approve", "test");
      const response = await tb.nextResponse();
      expect(response).toMatchObject({
        id: 1,
        result: { echo: { name: "shell_exec", arguments: { cmd: "ls" } } },
      });
    } finally {
      await tb.shutdown();
    }
  });
});

describe("ask path: deny -> MCP error", () => {
  it("a shell_exec call denied by a human returns an MCP error to the client", async () => {
    const queue = new ApprovalQueue({ timeoutMs: 5_000, pendingDir: resolve(tmp, "pending") });
    const tb = startTestbed(queue);
    try {
      tb.send({
        jsonrpc: "2.0",
        id: 7,
        method: "tools/call",
        params: { name: "shell_exec", arguments: { cmd: "rm -rf /" } },
      });
      await new Promise<void>((res) => {
        const t = setInterval(() => {
          if (queue.size === 1) {
            clearInterval(t);
            res();
          }
        }, 5);
      });
      const id = queue.list()[0]!.id;
      queue.resolve(id, "deny", "test");
      const response = await tb.nextResponse();
      expect(response).toMatchObject({
        id: 7,
        error: { code: AIRLOCK_DENIED_CODE },
      });
    } finally {
      await tb.shutdown();
    }
  });
});

describe("ask path: timeout -> deny", () => {
  it("an unresolved approval times out into an MCP error", async () => {
    const queue = new ApprovalQueue({ timeoutMs: 100, pendingDir: resolve(tmp, "pending") });
    const tb = startTestbed(queue);
    try {
      tb.send({
        jsonrpc: "2.0",
        id: 9,
        method: "tools/call",
        params: { name: "shell_exec", arguments: { cmd: "ls" } },
      });
      const response = await tb.nextResponse();
      expect(response).toMatchObject({
        id: 9,
        error: { code: AIRLOCK_DENIED_CODE },
      });
      const errMsg = (response as { error: { message: string } }).error.message;
      expect(errMsg).toMatch(/timed out|deny/i);
    } finally {
      await tb.shutdown();
    }
  });
});

describe("ask path: concurrency", () => {
  it("two concurrent asks don't block other traffic and each resolves independently", async () => {
    const queue = new ApprovalQueue({ timeoutMs: 5_000, pendingDir: resolve(tmp, "pending") });
    const tb = startTestbed(queue);
    try {
      // Send three asks back-to-back.
      tb.send({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name: "shell_exec", arguments: { cmd: "a" } } });
      tb.send({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "shell_exec", arguments: { cmd: "b" } } });
      tb.send({ jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "shell_exec", arguments: { cmd: "c" } } });
      // Send a plain read in between — that should round-trip *immediately*
      // because the ask path is non-blocking.
      tb.send({ jsonrpc: "2.0", id: 100, method: "tools/call", params: { name: "read_file", arguments: { path: "/x" } } });

      // The plain read should arrive while all three asks are still pending.
      const readResp = await tb.nextResponse();
      expect(readResp).toMatchObject({ id: 100, result: { echo: { name: "read_file" } } });
      expect(queue.size).toBe(3);

      // Now resolve the three asks in reverse order: deny 1, approve 2, approve 3.
      const pendingIds = queue.list();
      // pendingIds order is enqueue order: [for id=1, for id=2, for id=3]
      queue.resolve(pendingIds[0]!.id, "deny", "test");
      queue.resolve(pendingIds[1]!.id, "approve", "test");
      queue.resolve(pendingIds[2]!.id, "approve", "test");

      const collected: JsonRpcMessage[] = [];
      while (collected.length < 3) collected.push(await tb.nextResponse());

      const byId = new Map<number, JsonRpcMessage>();
      for (const r of collected) byId.set((r as { id: number }).id, r);

      // id=1 should be denied (error code), id=2 and id=3 should be the echo result.
      expect(byId.get(1)).toMatchObject({ error: { code: AIRLOCK_DENIED_CODE } });
      expect(byId.get(2)).toMatchObject({ result: { echo: { name: "shell_exec", arguments: { cmd: "b" } } } });
      expect(byId.get(3)).toMatchObject({ result: { echo: { name: "shell_exec", arguments: { cmd: "c" } } } });
    } finally {
      await tb.shutdown();
    }
  });
});
