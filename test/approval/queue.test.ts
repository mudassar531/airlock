import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { mkdtempSync, rmSync, writeFileSync, readdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { resolve, join } from "node:path";

import { ApprovalQueue } from "../../src/approval/queue.js";
import { watchPendingResolutions } from "../../src/approval/watcher.js";

let tmp: string;

beforeEach(() => {
  tmp = mkdtempSync(resolve(tmpdir(), "airlock-approval-"));
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

describe("ApprovalQueue", () => {
  it("resolves with 'approve' when resolve(approve) is called", async () => {
    const q = new ApprovalQueue({ timeoutMs: 10_000, pendingDir: tmp });
    const { summary, promise } = q.enqueue({
      sessionId: "s1",
      tool: "shell_exec",
      capability: "shell",
      operation: "execute",
      risk: "high",
      argsRedacted: { cmd: "ls" },
      ruleName: "confirm-shell-exec",
      reason: "test",
    });
    expect(summary.id).toMatch(/^[a-f0-9]{12}$/);
    queueMicrotask(() => q.resolve(summary.id, "approve", "cli"));
    const result = await promise;
    expect(result.resolution).toBe("approve");
    expect(result.resolvedBy).toBe("cli");
    expect(result.waitedMs).toBeGreaterThanOrEqual(0);
  });

  it("resolves with 'deny' when resolve(deny) is called", async () => {
    const q = new ApprovalQueue({ timeoutMs: 10_000, pendingDir: tmp });
    const { summary, promise } = q.enqueue({
      sessionId: "s1",
      tool: "x",
      argsRedacted: {},
      reason: "test",
    });
    queueMicrotask(() => q.resolve(summary.id, "deny", "cli"));
    const result = await promise;
    expect(result.resolution).toBe("deny");
  });

  it("times out to 'deny' when nothing resolves it", async () => {
    const q = new ApprovalQueue({ timeoutMs: 50, pendingDir: tmp });
    const { promise } = q.enqueue({
      sessionId: "s1",
      tool: "x",
      argsRedacted: {},
      reason: "test",
    });
    const result = await promise;
    expect(result.resolution).toBe("timeout");
    expect(result.resolvedBy).toBe("timeout");
    expect(result.waitedMs).toBeGreaterThanOrEqual(50);
  });

  it("handles concurrent approvals independently (no deadlock)", async () => {
    const q = new ApprovalQueue({ timeoutMs: 10_000, pendingDir: tmp });
    const reqs = Array.from({ length: 5 }, (_, i) =>
      q.enqueue({ sessionId: "s1", tool: `t_${i}`, argsRedacted: { i }, reason: "test" }),
    );
    // Resolve them out of order
    q.resolve(reqs[2]!.summary.id, "deny", "cli");
    q.resolve(reqs[0]!.summary.id, "approve", "cli");
    q.resolve(reqs[4]!.summary.id, "approve", "cli");
    q.resolve(reqs[1]!.summary.id, "deny", "cli");
    q.resolve(reqs[3]!.summary.id, "approve", "cli");

    const results = await Promise.all(reqs.map((r) => r.promise));
    expect(results.map((r) => r.resolution)).toEqual([
      "approve",
      "deny",
      "deny",
      "approve",
      "approve",
    ]);
    expect(q.size).toBe(0);
  });

  it("writes a pending JSON file and removes it on resolution", async () => {
    const q = new ApprovalQueue({ timeoutMs: 10_000, pendingDir: tmp });
    const { summary, promise } = q.enqueue({
      sessionId: "s1",
      tool: "x",
      argsRedacted: {},
      reason: "test",
    });
    expect(readdirSync(tmp).filter((n) => n.endsWith(".json"))).toEqual([
      `${summary.id}.json`,
    ]);
    q.resolve(summary.id, "approve", "cli");
    await promise;
    expect(readdirSync(tmp)).not.toContain(`${summary.id}.json`);
  });

  it("supports resolveFromDisk for out-of-band approval", async () => {
    const q = new ApprovalQueue({ timeoutMs: 10_000, pendingDir: tmp });
    const { summary, promise } = q.enqueue({
      sessionId: "s1",
      tool: "x",
      argsRedacted: {},
      reason: "test",
    });
    writeFileSync(join(tmp, `${summary.id}.resolution`), "approve\n");
    expect(q.resolveFromDisk(summary.id)).toBe(true);
    const result = await promise;
    expect(result.resolution).toBe("approve");
    expect(result.resolvedBy).toBe("out-of-band");
  });

  it("returns false when resolving an unknown id", () => {
    const q = new ApprovalQueue({ timeoutMs: 10_000, pendingDir: tmp });
    expect(q.resolve("nonexistent", "approve", "cli")).toBe(false);
  });

  it("fires onEnqueue with the summary", () => {
    const seen: string[] = [];
    const q = new ApprovalQueue({
      timeoutMs: 10_000,
      pendingDir: tmp,
      onEnqueue: (req) => seen.push(req.tool),
    });
    q.enqueue({ sessionId: "s", tool: "t1", argsRedacted: {}, reason: "" });
    q.enqueue({ sessionId: "s", tool: "t2", argsRedacted: {}, reason: "" });
    expect(seen).toEqual(["t1", "t2"]);
  });

  it("shutdown resolves all pending as deny", async () => {
    const q = new ApprovalQueue({ timeoutMs: 10_000, pendingDir: tmp });
    const a = q.enqueue({ sessionId: "s", tool: "a", argsRedacted: {}, reason: "" });
    const b = q.enqueue({ sessionId: "s", tool: "b", argsRedacted: {}, reason: "" });
    q.shutdown();
    const [ra, rb] = await Promise.all([a.promise, b.promise]);
    expect(ra.resolution).toBe("deny");
    expect(rb.resolution).toBe("deny");
    expect(ra.resolvedBy).toBe("shutdown");
  });
});

describe("watchPendingResolutions", () => {
  it("polls and resolves on a dropped .resolution file", async () => {
    const q = new ApprovalQueue({ timeoutMs: 10_000, pendingDir: tmp });
    const { summary, promise } = q.enqueue({
      sessionId: "s",
      tool: "x",
      argsRedacted: {},
      reason: "",
    });
    const handle = watchPendingResolutions(tmp, q);
    try {
      // Write resolution after a short delay so the watcher must observe it.
      setTimeout(() => {
        writeFileSync(join(tmp, `${summary.id}.resolution`), "deny\n");
      }, 100);
      const result = await promise;
      expect(result.resolution).toBe("deny");
      expect(result.resolvedBy).toBe("out-of-band");
    } finally {
      handle.stop();
    }
  });
});
