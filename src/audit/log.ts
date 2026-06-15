/**
 * Tamper-evident append-only audit log.
 *
 * Wire format: JSONL at `~/.airlock/audit.log`, one entry per line. Each
 * entry carries `prevHash` (the previous entry's `hash`) and `hash`, where
 *
 *   hash = sha256_hex( canonicalJSON(entry without `hash`) || prevHash )
 *
 * `prevHash` is the empty string for the genesis entry. The chain is
 * tamper-evident: changing, inserting, deleting, or reordering any entry
 * breaks every subsequent hash and `airlock verify` reports the first
 * broken line.
 *
 * Redaction (`audit/redact.ts`) runs on every value before serialization.
 * No raw secret ever lands on disk.
 *
 * Determinism: hashes use canonical JSON (sorted keys) so the same logical
 * entry produces the same hash across runs and platforms.
 */

import { appendFileSync, readFileSync, existsSync, statSync } from "node:fs";
import { createHash } from "node:crypto";

import {
  redact,
  canonicalJSONStringify,
} from "./redact.js";
import { ensureAirlockHome, airlockPaths, type AirlockPaths } from "../config.js";

export type Verdict = "allow" | "deny" | "ask" | "log";

export interface AuditEntryInput {
  sessionId: string;
  /** The MCP tool name (e.g. `read_file`). For non-tools/call entries, the method name. */
  tool: string;
  /** Capability the call touches (filesystem, shell, network, ...). Filled in by Phase 3. */
  capability?: string;
  /** Operation type (read, write, execute, ...). Filled in by Phase 3. */
  operation?: string;
  /** Risk label (low | medium | high | critical). Filled in by Phase 3. */
  risk?: string;
  /** Whether the lethal-trifecta tracker fired on this call. Phase 3. */
  trifecta?: boolean;
  /** Raw tool arguments. Will be redacted before write. */
  args: unknown;
  verdict: Verdict;
  /** Human-readable explanation of the verdict. */
  reason: string;
  /** Name of the policy rule that matched, if any. */
  ruleName?: string;
  /** End-to-end latency added by Airlock for this call, in milliseconds. */
  latencyMs: number;
  /** Who/what resolved the verdict for `ask`: `cli`, `webhook`, `timeout`, etc. */
  resolvedBy?: string;
  /** How long the call waited for a human, in ms. Zero for non-`ask` paths. */
  waitedMs?: number;
}

export interface AuditEntry extends AuditEntryInput {
  ts: string;
  seq: number;
  argsRedacted: unknown;
  prevHash: string;
  hash: string;
}

/**
 * Append-only audit log. Constructor reads the tail to recover the last
 * `seq` and `hash` so concurrent runs of `airlock wrap` continue the same
 * chain (process-level locking is out of scope for v0.1.0; the worst case
 * if two writers race is a small reordering that `airlock verify` still
 * detects, not a silent failure).
 */
export class AuditLog {
  private readonly paths: AirlockPaths;
  private lastSeq: number;
  private lastHash: string;

  constructor(paths: AirlockPaths = airlockPaths()) {
    this.paths = ensureAirlockHome(paths);
    const tail = readChainTail(paths.auditLog);
    this.lastSeq = tail.seq;
    this.lastHash = tail.hash;
  }

  /** Append one entry, with full redaction + hash linkage. Returns the written entry. */
  append(input: Omit<AuditEntryInput, "args"> & { args: unknown }): AuditEntry {
    const argsRedacted = redact(input.args);
    const seq = ++this.lastSeq;
    const prevHash = this.lastHash;
    const ts = new Date().toISOString();

    // Strip raw args from the on-disk record; only `argsRedacted` is written.
    const { args: _raw, ...rest } = input;
    void _raw;
    const draft = {
      ts,
      seq,
      prevHash,
      argsRedacted,
      ...rest,
    };

    const hash = sha256Hex(canonicalJSONStringify(draft) + prevHash);
    const entry: AuditEntry = {
      ...input,
      args: undefined, // never persisted; placeholder for type compatibility
      ts,
      seq,
      argsRedacted,
      prevHash,
      hash,
    };
    // The on-disk shape excludes `args` (only argsRedacted). We write the
    // canonical form so a reader hashing the entry minus `hash` reproduces
    // it bit-for-bit.
    const onDisk = { ...draft, hash };
    appendFileSync(this.paths.auditLog, canonicalJSONStringify(onDisk) + "\n", { mode: 0o600 });
    this.lastHash = hash;
    return entry;
  }

  /** Read all entries (recent first). For human display by `airlock log`. */
  readAll(): OnDiskEntry[] {
    return readEntries(this.paths.auditLog);
  }

  /** Current chain head — useful for tests and signing. */
  head(): { seq: number; hash: string } {
    return { seq: this.lastSeq, hash: this.lastHash };
  }
}

/** Shape of an entry as persisted to disk (no `args`, sorted-key canonical JSON). */
export interface OnDiskEntry {
  ts: string;
  seq: number;
  sessionId: string;
  tool: string;
  capability?: string;
  operation?: string;
  risk?: string;
  trifecta?: boolean;
  argsRedacted: unknown;
  verdict: Verdict;
  reason: string;
  ruleName?: string;
  latencyMs: number;
  resolvedBy?: string;
  waitedMs?: number;
  prevHash: string;
  hash: string;
}

function readChainTail(path: string): { seq: number; hash: string } {
  if (!existsSync(path)) return { seq: 0, hash: "" };
  let st;
  try {
    st = statSync(path);
  } catch {
    return { seq: 0, hash: "" };
  }
  if (st.size === 0) return { seq: 0, hash: "" };
  // Cheap and correct: read the whole file and take the last non-empty line.
  // Audit logs in practice are small (KB-MB range for a single session).
  // If this becomes a hot path, replace with a tail-reader.
  const lines = readFileSync(path, "utf8").split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line || line.length === 0) continue;
    try {
      const entry = JSON.parse(line) as OnDiskEntry;
      if (typeof entry.seq === "number" && typeof entry.hash === "string") {
        return { seq: entry.seq, hash: entry.hash };
      }
    } catch {
      // skip malformed
    }
  }
  return { seq: 0, hash: "" };
}

function readEntries(path: string): OnDiskEntry[] {
  if (!existsSync(path)) return [];
  const out: OnDiskEntry[] = [];
  const lines = readFileSync(path, "utf8").split("\n");
  for (const line of lines) {
    if (!line) continue;
    try {
      out.push(JSON.parse(line) as OnDiskEntry);
    } catch {
      // skip; verify() will flag corruption
    }
  }
  return out;
}

function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Verify the audit chain. Returns the first broken entry's seq (and reason)
 * or `null` if the chain is intact.
 */
export interface VerifyResult {
  ok: boolean;
  /** Number of entries in the chain. */
  total: number;
  /** seq of the first broken entry, or null if intact. */
  firstBrokenSeq: number | null;
  reason?: string;
}

export function verifyChain(path: string): VerifyResult {
  if (!existsSync(path)) {
    return { ok: true, total: 0, firstBrokenSeq: null };
  }
  const lines = readFileSync(path, "utf8").split("\n");
  let prevHash = "";
  let expectedSeq = 0;
  let total = 0;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    let entry: OnDiskEntry;
    try {
      entry = JSON.parse(line) as OnDiskEntry;
    } catch (err) {
      return {
        ok: false,
        total,
        firstBrokenSeq: expectedSeq + 1,
        reason: `line ${i + 1} is not valid JSON: ${(err as Error).message}`,
      };
    }
    total++;
    expectedSeq++;
    if (entry.seq !== expectedSeq) {
      return {
        ok: false,
        total,
        firstBrokenSeq: entry.seq ?? expectedSeq,
        reason: `seq gap: expected ${expectedSeq}, got ${entry.seq}`,
      };
    }
    if (entry.prevHash !== prevHash) {
      return {
        ok: false,
        total,
        firstBrokenSeq: entry.seq,
        reason: `prevHash mismatch at seq=${entry.seq}: expected '${prevHash}', got '${entry.prevHash}'`,
      };
    }
    const { hash: storedHash, ...withoutHash } = entry;
    const expectedHash = sha256Hex(canonicalJSONStringify(withoutHash) + prevHash);
    if (storedHash !== expectedHash) {
      return {
        ok: false,
        total,
        firstBrokenSeq: entry.seq,
        reason: `hash mismatch at seq=${entry.seq}: entry has been tampered with`,
      };
    }
    prevHash = storedHash;
  }
  return { ok: true, total, firstBrokenSeq: null };
}
