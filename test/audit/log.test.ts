import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve } from "node:path";

import { AuditLog, verifyChain } from "../../src/audit/log.js";
import { airlockPaths } from "../../src/config.js";
import { REDACTED } from "../../src/audit/redact.js";
import {
  generateKeypair,
  loadPrivateKey,
  loadPublicKey,
  signString,
  verifyString,
} from "../../src/audit/sign.js";

let tmp: string;
let originalEnv: string | undefined;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), "airlock-audit-"));
  originalEnv = process.env.AIRLOCK_HOME;
  process.env.AIRLOCK_HOME = tmp;
});

afterEach(() => {
  if (originalEnv === undefined) delete process.env.AIRLOCK_HOME;
  else process.env.AIRLOCK_HOME = originalEnv;
  try {
    rmSync(tmp, { recursive: true, force: true });
  } catch {
    // best effort
  }
});

describe("AuditLog", () => {
  it("appends an entry and chains hashes", () => {
    const log = new AuditLog(airlockPaths(tmp));
    const e1 = log.append({
      sessionId: "s1",
      tool: "read_file",
      args: { path: "/tmp/x" },
      verdict: "allow",
      reason: "phase 2 default",
      latencyMs: 5,
    });
    const e2 = log.append({
      sessionId: "s1",
      tool: "http_post",
      args: { url: "https://example.com" },
      verdict: "allow",
      reason: "phase 2 default",
      latencyMs: 7,
    });
    expect(e1.seq).toBe(1);
    expect(e1.prevHash).toBe("");
    expect(e2.seq).toBe(2);
    expect(e2.prevHash).toBe(e1.hash);
    expect(e1.hash).not.toEqual(e2.hash);
  });

  it("redacts arguments before writing them to disk", () => {
    const log = new AuditLog(airlockPaths(tmp));
    const fakeSecret = "github_pat_11A62SCNI0CrmevyHFSbojABCDEFGHIJKLMNOPQRSTUVWXYZ";
    log.append({
      sessionId: "s1",
      tool: "http_post",
      args: {
        url: "https://api.example.com/leak",
        headers: { authorization: `Bearer ${fakeSecret}` },
        body: { apiKey: fakeSecret, note: "ship it" },
      },
      verdict: "allow",
      reason: "test",
      latencyMs: 1,
    });
    const onDisk = readFileSync(airlockPaths(tmp).auditLog, "utf8");
    expect(onDisk).not.toContain(fakeSecret);
    expect(onDisk).toContain(REDACTED);
  });

  it("verifyChain reports OK for an intact chain", () => {
    const log = new AuditLog(airlockPaths(tmp));
    for (let i = 0; i < 5; i++) {
      log.append({
        sessionId: "s1",
        tool: `tool_${i}`,
        args: { i },
        verdict: "allow",
        reason: "test",
        latencyMs: i,
      });
    }
    const result = verifyChain(airlockPaths(tmp).auditLog);
    expect(result.ok).toBe(true);
    expect(result.total).toBe(5);
    expect(result.firstBrokenSeq).toBeNull();
  });

  it("verifyChain detects a tampered entry", () => {
    const log = new AuditLog(airlockPaths(tmp));
    for (let i = 0; i < 3; i++) {
      log.append({
        sessionId: "s1",
        tool: `tool_${i}`,
        args: { i },
        verdict: "allow",
        reason: "test",
        latencyMs: i,
      });
    }
    const path = airlockPaths(tmp).auditLog;
    const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
    // Tamper with the second entry's reason in-place; rewrite the file.
    const entry = JSON.parse(lines[1]!);
    entry.reason = "MUTATED";
    lines[1] = JSON.stringify(entry);
    writeFileSync(path, lines.join("\n") + "\n");

    const result = verifyChain(path);
    expect(result.ok).toBe(false);
    expect(result.firstBrokenSeq).toBe(2);
    expect(result.reason).toMatch(/tampered|hash mismatch/i);
  });

  it("verifyChain detects a deleted entry (seq gap)", () => {
    const log = new AuditLog(airlockPaths(tmp));
    for (let i = 0; i < 3; i++) {
      log.append({
        sessionId: "s1",
        tool: `tool_${i}`,
        args: { i },
        verdict: "allow",
        reason: "test",
        latencyMs: i,
      });
    }
    const path = airlockPaths(tmp).auditLog;
    const lines = readFileSync(path, "utf8").split("\n").filter(Boolean);
    // Remove line index 1 (seq=2)
    lines.splice(1, 1);
    writeFileSync(path, lines.join("\n") + "\n");
    const result = verifyChain(path);
    expect(result.ok).toBe(false);
    // The first remaining line at position 2 has seq=3 but we expect seq=2
    expect(result.firstBrokenSeq).toBe(3);
  });

  it("survives reopen and continues the chain at the right seq", () => {
    const log1 = new AuditLog(airlockPaths(tmp));
    log1.append({
      sessionId: "s1",
      tool: "a",
      args: {},
      verdict: "allow",
      reason: "",
      latencyMs: 1,
    });
    log1.append({
      sessionId: "s1",
      tool: "b",
      args: {},
      verdict: "allow",
      reason: "",
      latencyMs: 1,
    });
    const log2 = new AuditLog(airlockPaths(tmp));
    const e3 = log2.append({
      sessionId: "s1",
      tool: "c",
      args: {},
      verdict: "allow",
      reason: "",
      latencyMs: 1,
    });
    expect(e3.seq).toBe(3);
    const result = verifyChain(airlockPaths(tmp).auditLog);
    expect(result.ok).toBe(true);
    expect(result.total).toBe(3);
  });
});

describe("audit/sign", () => {
  it("generates a keypair on disk", () => {
    const paths = airlockPaths(tmp);
    const out = generateKeypair(paths);
    expect(out.privateKeyPath).toBe(paths.privateKeyPath);
    expect(readFileSync(out.privateKeyPath, "utf8")).toContain("BEGIN PRIVATE KEY");
    expect(readFileSync(out.publicKeyPath, "utf8")).toContain("BEGIN PUBLIC KEY");
  });

  it("signs and verifies a payload (head hash)", () => {
    const paths = airlockPaths(tmp);
    generateKeypair(paths);
    const priv = loadPrivateKey(paths.privateKeyPath);
    const pub = loadPublicKey(paths.publicKeyPath);
    const payload = "deadbeef".repeat(8);
    const sig = signString(payload, priv);
    expect(verifyString(payload, sig, pub)).toBe(true);
    expect(verifyString(payload + "X", sig, pub)).toBe(false);
  });

  it("is idempotent without --force", () => {
    const paths = airlockPaths(tmp);
    generateKeypair(paths);
    const first = readFileSync(paths.privateKeyPath, "utf8");
    generateKeypair(paths);
    const second = readFileSync(paths.privateKeyPath, "utf8");
    expect(second).toBe(first);
  });

  it("rotates when --force is true", () => {
    const paths = airlockPaths(tmp);
    generateKeypair(paths);
    const first = readFileSync(paths.privateKeyPath, "utf8");
    generateKeypair(paths, true);
    const second = readFileSync(paths.privateKeyPath, "utf8");
    expect(second).not.toBe(first);
  });
});
