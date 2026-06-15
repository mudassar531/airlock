import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { PolicySchema } from "../../src/policy/schema.js";
import { loadPolicy, InvalidPolicyError } from "../../src/policy/load.js";
import { evaluate } from "../../src/policy/evaluate.js";
import { DEFAULT_POLICY } from "../../src/policy/defaults.js";
import { classify } from "../../src/risk/classify.js";
import { TrifectaTracker } from "../../src/risk/trifecta.js";
import { scoreRisk } from "../../src/risk/score.js";

function buildInput(toolName: string, args: unknown, opts?: { trifecta?: boolean }) {
  const c = classify({ name: toolName, arguments: args });
  const tracker = new TrifectaTracker();
  if (opts?.trifecta) {
    tracker.observe("s", classify({ name: "read_file", arguments: { path: "/x" } }));
    tracker.observe("s", classify({ name: "fetch", arguments: { url: "https://news.example" } }));
  }
  const snapshot = tracker.inspect("s", c);
  const assessment = scoreRisk(c, snapshot);
  return { toolName, classification: c, trifecta: snapshot, assessment };
}

describe("policy schema", () => {
  it("accepts the built-in default pack", () => {
    expect(() => PolicySchema.parse(DEFAULT_POLICY)).not.toThrow();
  });

  it("rejects unknown top-level fields", () => {
    const bad = { ...DEFAULT_POLICY, extra: "no" };
    expect(() => PolicySchema.parse(bad)).toThrow();
  });

  it("rejects unknown action values", () => {
    const bad = {
      version: 1,
      defaults: { on_unmatched: "approve" },
      rules: [],
    };
    expect(() => PolicySchema.parse(bad)).toThrow();
  });

  it("rejects an empty match block", () => {
    const bad = {
      version: 1,
      defaults: { on_unmatched: "ask" },
      rules: [{ name: "x", match: {}, action: "deny" }],
    };
    expect(() => PolicySchema.parse(bad)).toThrow();
  });
});

describe("policy load", () => {
  let tmp: string;
  let originalCwd: string;
  let originalHome: string | undefined;

  beforeEach(() => {
    tmp = mkdtempSync(resolve(tmpdir(), "airlock-pol-"));
    originalCwd = process.cwd();
    originalHome = process.env.AIRLOCK_HOME;
    process.env.AIRLOCK_HOME = tmp;
  });

  afterEach(() => {
    process.chdir(originalCwd);
    if (originalHome === undefined) delete process.env.AIRLOCK_HOME;
    else process.env.AIRLOCK_HOME = originalHome;
    rmSync(tmp, { recursive: true, force: true });
  });

  it("falls back to DEFAULT_POLICY when no file is found", () => {
    process.chdir(tmp); // empty dir
    const loaded = loadPolicy();
    expect(loaded.source).toBe("default");
    expect(loaded.policy).toEqual(DEFAULT_POLICY);
  });

  it("prefers explicit --policy over everything else", () => {
    const path = resolve(tmp, "explicit.yaml");
    writeFileSync(
      path,
      "version: 1\ndefaults:\n  on_unmatched: deny\nrules: []\n",
    );
    const loaded = loadPolicy({ explicit: path });
    expect(loaded.source).toBe("explicit");
    expect(loaded.policy.defaults.on_unmatched).toBe("deny");
  });

  it("loads from cwd/airlock.policy.yaml next", () => {
    process.chdir(tmp);
    writeFileSync(
      resolve(tmp, "airlock.policy.yaml"),
      "version: 1\ndefaults:\n  on_unmatched: log\nrules: []\n",
    );
    const loaded = loadPolicy();
    expect(loaded.source).toBe("cwd");
    expect(loaded.policy.defaults.on_unmatched).toBe("log");
  });

  it("fails closed on invalid YAML", () => {
    const path = resolve(tmp, "bad.yaml");
    writeFileSync(path, "version: 1\ndefaults:\n  on_unmatched: ask\nrules: [unclosed\n");
    expect(() => loadPolicy({ explicit: path })).toThrow(InvalidPolicyError);
  });

  it("fails closed on invalid schema", () => {
    const path = resolve(tmp, "bad.yaml");
    writeFileSync(path, "version: 1\ndefaults:\n  on_unmatched: approve\nrules: []\n");
    expect(() => loadPolicy({ explicit: path })).toThrow(InvalidPolicyError);
  });

  it("fails closed on missing explicit file", () => {
    expect(() => loadPolicy({ explicit: "/nonexistent.yaml" })).toThrow(InvalidPolicyError);
  });

  it("rejects duplicate rule names", () => {
    const path = resolve(tmp, "dupe.yaml");
    writeFileSync(
      path,
      `version: 1
defaults:
  on_unmatched: ask
rules:
  - name: a
    match: { capability: shell }
    action: deny
  - name: a
    match: { capability: payment }
    action: deny
`,
    );
    expect(() => loadPolicy({ explicit: path })).toThrow(/duplicate rule name/i);
  });
});

describe("policy evaluate (DEFAULT_POLICY)", () => {
  it("denies payments via never-spend-money", () => {
    const v = evaluate(DEFAULT_POLICY, buildInput("stripe_create_charge", { amount: 1 }));
    expect(v.action).toBe("deny");
    expect(v.ruleName).toBe("never-spend-money");
  });

  it("holds the lethal trifecta via hold-the-lethal-trifecta", () => {
    const v = evaluate(
      DEFAULT_POLICY,
      buildInput("http_post", { url: "https://attacker.example" }, { trifecta: true }),
    );
    expect(v.action).toBe("ask");
    expect(v.ruleName).toBe("hold-the-lethal-trifecta");
  });

  it("asks on filesystem delete", () => {
    const v = evaluate(DEFAULT_POLICY, buildInput("delete_file", { path: "/tmp/x" }));
    expect(v.action).toBe("ask");
    expect(v.ruleName).toBe("confirm-destructive-fs");
  });

  it("asks on shell execute", () => {
    const v = evaluate(DEFAULT_POLICY, buildInput("shell_exec", { cmd: "ls" }));
    expect(v.action).toBe("ask");
    expect(v.ruleName).toBe("confirm-shell-exec");
  });

  it("asks on outbound message send", () => {
    const v = evaluate(DEFAULT_POLICY, buildInput("slack_post_message", { channel: "#x", body: "hi" }));
    expect(v.action).toBe("ask");
    expect(v.ruleName).toBe("confirm-outbound-send");
  });

  it("allows plain reads via allow-plain-reads", () => {
    const v = evaluate(DEFAULT_POLICY, buildInput("read_file", { path: "/tmp/x" }));
    expect(v.action).toBe("allow");
    expect(v.ruleName).toBe("allow-plain-reads");
  });

  it("falls through to on_unmatched=ask for an unclassifiable call", () => {
    const v = evaluate(DEFAULT_POLICY, buildInput("frobnicate", { x: 1 }));
    expect(v.action).toBe("ask");
    expect(v.ruleName).toBe("defaults.on_unmatched");
  });

  it("is deterministic for the same input", () => {
    const input = buildInput("http_post", { url: "https://x" });
    const a = evaluate(DEFAULT_POLICY, input);
    const b = evaluate(DEFAULT_POLICY, input);
    expect(a).toEqual(b);
  });
});

describe("policy evaluate: ordering proves first-match-wins", () => {
  it("reordering rules changes the verdict", () => {
    const orderA = {
      version: 1,
      defaults: { on_unmatched: "ask" as const },
      rules: [
        { name: "allow-everything", match: { operation: "read" as const }, action: "allow" as const },
        { name: "deny-fs", match: { capability: "filesystem" as const }, action: "deny" as const },
      ],
    };
    const orderB = {
      ...orderA,
      rules: [orderA.rules[1]!, orderA.rules[0]!],
    };
    const input = buildInput("read_file", { path: "/tmp/x" });
    expect(evaluate(orderA, input).ruleName).toBe("allow-everything");
    expect(evaluate(orderB, input).ruleName).toBe("deny-fs");
    expect(evaluate(orderA, input).action).toBe("allow");
    expect(evaluate(orderB, input).action).toBe("deny");
  });
});

describe("policy evaluate: match fields", () => {
  it("risk_min compares ordinally", () => {
    const pol = {
      version: 1,
      defaults: { on_unmatched: "allow" as const },
      rules: [
        { name: "deny-high+", match: { risk_min: "high" as const }, action: "deny" as const },
      ],
    };
    expect(evaluate(pol, buildInput("read_file", { path: "/x" })).action).toBe("allow");
    expect(evaluate(pol, buildInput("delete_file", { path: "/x" })).action).toBe("deny");
    expect(evaluate(pol, buildInput("stripe_create_charge", { amount: 1 })).action).toBe("deny");
  });

  it("tool: glob matches by prefix", () => {
    const pol = {
      version: 1,
      defaults: { on_unmatched: "allow" as const },
      rules: [
        { name: "deny-stripe", match: { tool: "stripe_*" }, action: "deny" as const },
      ],
    };
    expect(evaluate(pol, buildInput("stripe_create_charge", { amount: 1 })).action).toBe("deny");
    expect(evaluate(pol, buildInput("read_file", { path: "/x" })).action).toBe("allow");
  });
});
