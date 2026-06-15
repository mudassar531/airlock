import { describe, it, expect } from "vitest";
import { classify } from "../../src/risk/classify.js";

describe("classify: built-in tool map", () => {
  it("read_file → filesystem/read", () => {
    const c = classify({ name: "read_file", arguments: { path: "/tmp/x" } });
    expect(c.capability).toBe("filesystem");
    expect(c.operation).toBe("read");
    expect(c.untrustedRead).toBeUndefined();
  });

  it("write_file → filesystem/write", () => {
    expect(classify({ name: "write_file", arguments: { path: "/x", content: "" } })).toMatchObject({
      capability: "filesystem",
      operation: "write",
    });
  });

  it("delete_file → filesystem/delete", () => {
    expect(classify({ name: "delete_file", arguments: { path: "/x" } })).toMatchObject({
      capability: "filesystem",
      operation: "delete",
    });
  });

  it("http_post → network/send", () => {
    expect(classify({ name: "http_post", arguments: { url: "https://x" } })).toMatchObject({
      capability: "network",
      operation: "send",
    });
  });

  it("fetch → network/read with untrustedRead=true", () => {
    const c = classify({ name: "fetch", arguments: { url: "https://example.com" } });
    expect(c.capability).toBe("network");
    expect(c.operation).toBe("read");
    expect(c.untrustedRead).toBe(true);
  });

  it("shell_exec → shell/execute", () => {
    expect(classify({ name: "shell_exec", arguments: { cmd: "ls" } })).toMatchObject({
      capability: "shell",
      operation: "execute",
    });
  });

  it("stripe_create_charge → payment/spend (critical territory)", () => {
    expect(classify({ name: "stripe_create_charge", arguments: { amount: 100 } })).toMatchObject({
      capability: "payment",
      operation: "spend",
    });
  });

  it("read_notes → marked as untrustedRead (a classic injection vector)", () => {
    const c = classify({ name: "read_notes", arguments: { id: "1" } });
    expect(c.untrustedRead).toBe(true);
  });

  it("is case-insensitive on tool name", () => {
    expect(classify({ name: "READ_FILE", arguments: {} })).toMatchObject({
      capability: "filesystem",
      operation: "read",
    });
  });
});

describe("classify: name heuristics for unknown tools", () => {
  it("delete_* → operation=delete", () => {
    expect(classify({ name: "delete_widget", arguments: {} }).operation).toBe("delete");
  });

  it("read_* → operation=read", () => {
    expect(classify({ name: "read_calendar", arguments: {} }).operation).toBe("read");
  });

  it("*_send / send_* → operation=send", () => {
    expect(classify({ name: "send_metric", arguments: {} }).operation).toBe("send");
    expect(classify({ name: "metric_send", arguments: {} }).operation).toBe("send");
  });

  it("shell-y names → capability=shell", () => {
    expect(classify({ name: "spawn_process", arguments: {} }).capability).toBe("shell");
  });

  it("payment-y names → capability=payment", () => {
    expect(classify({ name: "create_invoice", arguments: {} }).capability).toBe("payment");
  });
});

describe("classify: argument-shape heuristics", () => {
  it("args.amount + currency → payment/spend even if name is opaque", () => {
    const c = classify({ name: "do_thing", arguments: { amount: 50, currency: "USD" } });
    expect(c).toMatchObject({ capability: "payment", operation: "spend" });
  });

  it("args.to + body → message/send", () => {
    const c = classify({ name: "do_thing", arguments: { to: "a@b.com", body: "hi" } });
    expect(c).toMatchObject({ capability: "message", operation: "send" });
  });

  it("args.url → network", () => {
    const c = classify({ name: "do_thing", arguments: { url: "https://x" } });
    expect(c.capability).toBe("network");
  });

  it("args.path → filesystem", () => {
    const c = classify({ name: "do_thing", arguments: { path: "/tmp" } });
    expect(c.capability).toBe("filesystem");
  });

  it("args.command → shell/execute", () => {
    expect(classify({ name: "do_thing", arguments: { command: "ls" } })).toMatchObject({
      capability: "shell",
      operation: "execute",
    });
  });

  it("non-loopback URL on a network/read upgrades untrustedRead", () => {
    const c = classify({ name: "fetch", arguments: { url: "https://example.com" } });
    expect(c.untrustedRead).toBe(true);
  });

  it("loopback URL is NOT marked untrustedRead", () => {
    const c = classify({ name: "fetch", arguments: { url: "http://127.0.0.1:8080" } });
    expect(c.untrustedRead).toBe(true); // built-in map says true; we keep that conservative default
  });
});

describe("classify: fallback to other/other", () => {
  it("totally unknown tool, no args → other/other", () => {
    const c = classify({ name: "frobnicate", arguments: {} });
    expect(c).toMatchObject({ capability: "other", operation: "other" });
  });
});
