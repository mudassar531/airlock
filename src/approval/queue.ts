/**
 * Pending-approval queue. When a verdict is `ask`, the interceptor enqueues
 * a request here; the queue returns a Promise that resolves on approve /
 * deny / timeout. Multiple pending approvals coexist without blocking each
 * other or the relay.
 *
 * Out-of-band resolution is supported via a per-approval JSON file written
 * to `~/.airlock/pending/<id>.json`. `airlock approve <id>` and
 * `airlock deny <id>` write a `<id>.resolution` file alongside it; the
 * running proxy watches the directory and resolves the matching pending
 * promise. This is how non-TTY hosts (Claude Desktop, etc.) can route a
 * decision back to a long-running `wrap` instance.
 *
 * Timeout default: 60s. On timeout the resolution is `deny`. Fail closed.
 */

import { randomUUID } from "node:crypto";
import { writeFileSync, unlinkSync, existsSync, readFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { airlockPaths, ensureAirlockHome } from "../config.js";

export type ApprovalResolution = "approve" | "deny" | "timeout";

export interface ApprovalRequestSummary {
  id: string;
  /** ISO timestamp when the approval was created. */
  ts: string;
  sessionId: string;
  tool: string;
  capability?: string;
  operation?: string;
  risk?: string;
  trifecta?: boolean;
  /** Redacted args, safe to display in a TTY prompt or desktop notification. */
  argsRedacted: unknown;
  ruleName?: string;
  reason: string;
}

export interface ApprovalRequest {
  summary: ApprovalRequestSummary;
  /** Promise that resolves with the final resolution. */
  promise: Promise<{ resolution: ApprovalResolution; resolvedBy: string; waitedMs: number }>;
}

export interface ApprovalQueueOptions {
  /** Default ms before an unresolved approval auto-denies. */
  timeoutMs?: number;
  /**
   * Where to drop the per-approval JSON for out-of-band resolution.
   * Defaults to `~/.airlock/pending`.
   */
  pendingDir?: string;
  /**
   * Called when a new approval is enqueued. Hosts wire this to a CLI prompt
   * (`approval/cli.ts`), a desktop notification (`approval/notify.ts`), or
   * any other channel.
   */
  onEnqueue?: (req: ApprovalRequestSummary, queue: ApprovalQueue) => void;
}

interface PendingState {
  summary: ApprovalRequestSummary;
  resolve: (result: { resolution: ApprovalResolution; resolvedBy: string; waitedMs: number }) => void;
  startedAt: number;
  timer: NodeJS.Timeout;
}

export class ApprovalQueue {
  private readonly timeoutMs: number;
  private readonly pendingDir: string;
  private readonly onEnqueue?: (req: ApprovalRequestSummary, queue: ApprovalQueue) => void;
  private readonly pending = new Map<string, PendingState>();

  constructor(opts: ApprovalQueueOptions = {}) {
    this.timeoutMs = opts.timeoutMs ?? 60_000;
    this.pendingDir = opts.pendingDir ?? airlockPaths().pendingDir;
    if (opts.onEnqueue) this.onEnqueue = opts.onEnqueue;
    try {
      mkdirSync(this.pendingDir, { recursive: true, mode: 0o700 });
    } catch {
      // best effort; ensureAirlockHome handles the canonical case
    }
  }

  /** Number of approvals currently waiting. */
  get size(): number {
    return this.pending.size;
  }

  /**
   * Enqueue an approval. Returns the summary (including id) plus a promise
   * that resolves with `{resolution, resolvedBy, waitedMs}`.
   */
  enqueue(
    fields: Omit<ApprovalRequestSummary, "id" | "ts">,
  ): ApprovalRequest {
    const id = shortId();
    const summary: ApprovalRequestSummary = {
      id,
      ts: new Date().toISOString(),
      ...fields,
    };
    // Drop the on-disk handle BEFORE setting up the promise so subscribers
    // observing the directory see it immediately.
    const pendingPath = join(this.pendingDir, `${id}.json`);
    try {
      ensureAirlockHome();
      writeFileSync(pendingPath, JSON.stringify(summary, null, 2) + "\n", {
        mode: 0o600,
      });
    } catch {
      // out-of-band resolution unavailable, but in-process still works
    }

    const promise = new Promise<{
      resolution: ApprovalResolution;
      resolvedBy: string;
      waitedMs: number;
    }>((resolve) => {
      const timer = setTimeout(() => {
        this.timeoutResolve(id);
      }, this.timeoutMs);
      // Allow the process to exit naturally when nothing else is pending.
      try {
        timer.unref();
      } catch {
        // not all runtimes support unref
      }
      this.pending.set(id, {
        summary,
        resolve,
        startedAt: Date.now(),
        timer,
      });
    });

    if (this.onEnqueue) {
      try {
        this.onEnqueue(summary, this);
      } catch {
        // notification failure must not break the approval flow
      }
    }

    return { summary, promise };
  }

  /**
   * Resolve an approval by id. `resolvedBy` is recorded in the audit log
   * (e.g. "cli", "out-of-band:approve", "timeout"). Returns false if the id
   * isn't pending (already resolved or never existed).
   */
  resolve(id: string, resolution: ApprovalResolution, resolvedBy: string): boolean {
    const state = this.pending.get(id);
    if (!state) return false;
    clearTimeout(state.timer);
    this.pending.delete(id);
    const waitedMs = Date.now() - state.startedAt;
    state.resolve({ resolution, resolvedBy, waitedMs });
    this.cleanupOnDisk(id);
    return true;
  }

  private timeoutResolve(id: string): void {
    const state = this.pending.get(id);
    if (!state) return;
    this.pending.delete(id);
    const waitedMs = Date.now() - state.startedAt;
    state.resolve({ resolution: "timeout", resolvedBy: "timeout", waitedMs });
    this.cleanupOnDisk(id);
  }

  private cleanupOnDisk(id: string): void {
    const pendingPath = join(this.pendingDir, `${id}.json`);
    const resolutionPath = join(this.pendingDir, `${id}.resolution`);
    for (const p of [pendingPath, resolutionPath]) {
      try {
        if (existsSync(p)) unlinkSync(p);
      } catch {
        // best effort
      }
    }
  }

  /** Test helper: cancel everything synchronously. */
  shutdown(): void {
    for (const [id, state] of this.pending.entries()) {
      clearTimeout(state.timer);
      state.resolve({ resolution: "deny", resolvedBy: "shutdown", waitedMs: 0 });
      this.cleanupOnDisk(id);
    }
    this.pending.clear();
  }

  /** Inspect the queue (read-only). For the `airlock approve --list` UX. */
  list(): ApprovalRequestSummary[] {
    return Array.from(this.pending.values()).map((s) => s.summary);
  }

  /**
   * Resolve via the on-disk channel. Called by the file watcher when a
   * `<id>.resolution` appears. Reads the file content (`"approve"` or
   * `"deny"`) and applies it.
   */
  resolveFromDisk(id: string): boolean {
    const resolutionPath = join(this.pendingDir, `${id}.resolution`);
    if (!existsSync(resolutionPath)) return false;
    let body = "";
    try {
      body = readFileSync(resolutionPath, "utf8").trim().toLowerCase();
    } catch {
      return false;
    }
    if (body === "approve" || body === "allow") {
      return this.resolve(id, "approve", "out-of-band");
    }
    if (body === "deny") {
      return this.resolve(id, "deny", "out-of-band");
    }
    return false;
  }
}

/** Short, URL-safe approval id derived from a v4 UUID. */
function shortId(): string {
  return randomUUID().replace(/-/g, "").slice(0, 12);
}
