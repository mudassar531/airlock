import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import { startHttpProxy, type HttpProxyHandle } from "../../src/proxy/httpProxy.js";

let tmp: string;
let echoPath: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), "airlock-http-"));
  echoPath = resolve(tmp, "echo.cjs");
  writeFileSync(
    echoPath,
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
  rmSync(tmp, { recursive: true, force: true });
});

async function startServer(): Promise<HttpProxyHandle> {
  return startHttpProxy({
    command: process.execPath,
    args: [echoPath],
    host: "127.0.0.1",
    port: 0, // ephemeral
  });
}

describe("startHttpProxy", () => {
  it("round-trips a tools/call over HTTP POST", async () => {
    const h = await startServer();
    try {
      const url = `http://127.0.0.1:${h.address.port}/mcp`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 42,
          method: "tools/call",
          params: { name: "echo", arguments: { x: 1 } },
        }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { id: number; result: { echo: unknown } };
      expect(body.id).toBe(42);
      expect(body.result.echo).toEqual({ name: "echo", arguments: { x: 1 } });
    } finally {
      await h.shutdown();
    }
  });

  it("rejects a request with a disallowed Origin", async () => {
    const h = await startServer();
    try {
      const url = `http://127.0.0.1:${h.address.port}/mcp`;
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "http://evil.example",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "echo", arguments: {} },
        }),
      });
      expect(res.status).toBe(403);
      const body = (await res.json()) as { error?: { message: string } };
      expect(body.error?.message).toMatch(/disallowed Origin/i);
    } finally {
      await h.shutdown();
    }
  });

  it("accepts a request with no Origin (curl/server-to-server)", async () => {
    const h = await startServer();
    try {
      const url = `http://127.0.0.1:${h.address.port}/mcp`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 5,
          method: "tools/call",
          params: { name: "echo", arguments: {} },
        }),
      });
      expect(res.status).toBe(200);
    } finally {
      await h.shutdown();
    }
  });

  it("accepts a request from an allowed localhost Origin", async () => {
    const h = await startServer();
    try {
      const url = `http://127.0.0.1:${h.address.port}/mcp`;
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "http://localhost:3000",
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 7,
          method: "tools/call",
          params: { name: "echo", arguments: {} },
        }),
      });
      expect(res.status).toBe(200);
    } finally {
      await h.shutdown();
    }
  });

  it("404s an unknown path", async () => {
    const h = await startServer();
    try {
      const url = `http://127.0.0.1:${h.address.port}/notmcp`;
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      expect(res.status).toBe(404);
    } finally {
      await h.shutdown();
    }
  });
});
