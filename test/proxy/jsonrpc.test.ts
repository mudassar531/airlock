import { describe, it, expect } from "vitest";
import {
  LineFramer,
  serializeMessage,
  isJsonRpcRequest,
  isJsonRpcNotification,
  isJsonRpcResponse,
  type JsonRpcRequest,
  type JsonRpcNotification,
  type JsonRpcSuccessResponse,
  type JsonRpcErrorResponse,
} from "../../src/proxy/jsonrpc.js";

describe("LineFramer", () => {
  it("yields nothing until a full line arrives", () => {
    const f = new LineFramer();
    f.append(Buffer.from('{"jsonrpc":"2.0","id"'));
    expect(f.readMessage()).toBeNull();
    f.append(Buffer.from(':1,"method":"ping"}'));
    expect(f.readMessage()).toBeNull(); // still no newline
    f.append(Buffer.from("\n"));
    const msg = f.readMessage();
    expect(msg).toEqual({ jsonrpc: "2.0", id: 1, method: "ping" });
  });

  it("yields multiple messages from a single chunk", () => {
    const f = new LineFramer();
    const a = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "a" });
    const b = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "b" });
    const c = JSON.stringify({ jsonrpc: "2.0", method: "notif" });
    f.append(Buffer.from(`${a}\n${b}\n${c}\n`));
    expect(f.readMessage()).toMatchObject({ id: 1, method: "a" });
    expect(f.readMessage()).toMatchObject({ id: 2, method: "b" });
    expect(f.readMessage()).toMatchObject({ method: "notif" });
    expect(f.readMessage()).toBeNull();
  });

  it("tolerates CRLF terminators", () => {
    const f = new LineFramer();
    f.append(Buffer.from('{"jsonrpc":"2.0","id":7,"method":"x"}\r\n'));
    expect(f.readMessage()).toEqual({
      jsonrpc: "2.0",
      id: 7,
      method: "x",
    });
  });

  it("skips empty lines silently", () => {
    const f = new LineFramer();
    f.append(Buffer.from('\n\n{"jsonrpc":"2.0","id":1,"method":"x"}\n'));
    expect(f.readMessage()).toMatchObject({ id: 1, method: "x" });
  });

  it("throws on invalid JSON so callers can decide how to handle it", () => {
    const f = new LineFramer();
    f.append(Buffer.from("{not-json\n"));
    expect(() => f.readMessage()).toThrow();
  });

  it("round-trips byte-faithfully when paired with serializeMessage", () => {
    const f = new LineFramer();
    const original: JsonRpcRequest = {
      jsonrpc: "2.0",
      id: "abc-123",
      method: "tools/call",
      params: {
        name: "search",
        arguments: { query: "hello", limit: 10, deep: { nested: ["a", "b"] } },
      },
    };
    f.append(serializeMessage(original));
    const parsed = f.readMessage();
    expect(parsed).toEqual(original);
  });

  it("survives a burst of 100 sequential messages without dropping", () => {
    const f = new LineFramer();
    const msgs: JsonRpcRequest[] = Array.from({ length: 100 }, (_, i) => ({
      jsonrpc: "2.0",
      id: i,
      method: "tools/call",
      params: { name: `tool_${i}`, arguments: { i } },
    }));
    const all = Buffer.concat(msgs.map((m) => serializeMessage(m)));
    f.append(all);
    const seen: unknown[] = [];
    while (true) {
      const m = f.readMessage();
      if (m === null) break;
      seen.push(m);
    }
    expect(seen).toHaveLength(100);
    expect(seen[0]).toEqual(msgs[0]);
    expect(seen[99]).toEqual(msgs[99]);
  });

  it("handles a chunk boundary in the middle of a UTF-8 multibyte sequence", () => {
    const f = new LineFramer();
    const payload = JSON.stringify({
      jsonrpc: "2.0",
      id: 1,
      method: "x",
      params: { greeting: "héllo 👋" },
    });
    const full = Buffer.from(payload + "\n", "utf8");
    // Split somewhere likely to break a multibyte char.
    const midpoint = Math.floor(full.length / 2);
    f.append(full.subarray(0, midpoint));
    f.append(full.subarray(midpoint));
    const msg = f.readMessage();
    expect(msg).toMatchObject({ params: { greeting: "héllo 👋" } });
  });
});

describe("type guards", () => {
  const req: JsonRpcRequest = { jsonrpc: "2.0", id: 1, method: "x" };
  const notif: JsonRpcNotification = { jsonrpc: "2.0", method: "n" };
  const res: JsonRpcSuccessResponse = { jsonrpc: "2.0", id: 1, result: {} };
  const err: JsonRpcErrorResponse = {
    jsonrpc: "2.0",
    id: 1,
    error: { code: -32600, message: "bad" },
  };

  it("distinguishes requests from notifications by the presence of id", () => {
    expect(isJsonRpcRequest(req)).toBe(true);
    expect(isJsonRpcRequest(notif)).toBe(false);
    expect(isJsonRpcNotification(req)).toBe(false);
    expect(isJsonRpcNotification(notif)).toBe(true);
  });

  it("identifies success and error responses", () => {
    expect(isJsonRpcResponse(res)).toBe(true);
    expect(isJsonRpcResponse(err)).toBe(true);
    expect(isJsonRpcResponse(req)).toBe(false);
    expect(isJsonRpcResponse(notif)).toBe(false);
  });

  it("rejects malformed inputs", () => {
    expect(isJsonRpcRequest(null)).toBe(false);
    expect(isJsonRpcRequest({ jsonrpc: "2.0", id: 1 })).toBe(false);
    expect(isJsonRpcRequest({ jsonrpc: "1.0", id: 1, method: "x" })).toBe(false);
  });
});

describe("serializeMessage", () => {
  it("appends exactly one trailing newline", () => {
    const out = serializeMessage({ jsonrpc: "2.0", id: 1, method: "x" });
    expect(out[out.length - 1]).toBe(0x0a);
    expect(out.toString("utf8").endsWith("\n")).toBe(true);
    // No double newlines in the body
    expect(out.toString("utf8").match(/\n/g)?.length).toBe(1);
  });
});
