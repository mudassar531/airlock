/**
 * Pre-write secret redaction for the audit log.
 *
 * The audit log is supposed to make agent behavior *more* inspectable. But if
 * an agent passes a real secret as a tool argument (API key, bearer token,
 * password, ssh key), naively logging it creates a brand-new leak that didn't
 * exist before Airlock ran. So every value that lands in the audit log passes
 * through `redact()` first — no exceptions.
 *
 * Redaction is a defense in depth, not a substitute for least-privilege. We
 * redact on three signals:
 *   1. The *key* the value is filed under (e.g. `apiKey`, `password`, `token`).
 *   2. The *shape* of the value (e.g. starts with `sk-`, looks like a JWT,
 *      looks like a long base64 / hex blob of high entropy).
 *   3. Known service prefixes (GitHub PAT `github_pat_`, OpenAI `sk-`,
 *      Anthropic `sk-ant-`, AWS `AKIA`, Slack `xox[abp]-`).
 *
 * False positives are acceptable. False negatives are not — if in doubt,
 * we redact.
 */

const SECRET_KEY_PATTERNS: RegExp[] = [
  /password/i,
  /passwd/i,
  /secret/i,
  /token/i,
  /api[_-]?key/i,
  /apikey/i,
  /auth(?:orization)?/i,
  /bearer/i,
  /credential/i,
  /private[_-]?key/i,
  /privatekey/i,
  /access[_-]?key/i,
  /client[_-]?secret/i,
  /session[_-]?id/i,
  /cookie/i,
];

/**
 * Common service-issued credential prefixes. These are conservative — they
 * fire on the *literal* token shapes, not generic high-entropy strings.
 */
const SECRET_VALUE_PREFIXES: RegExp[] = [
  /^sk-[A-Za-z0-9_-]{12,}/,            // OpenAI (sk-, sk-proj-)
  /^sk-ant-[A-Za-z0-9_-]{12,}/,        // Anthropic
  /^github_pat_[A-Za-z0-9_]{20,}/,     // GitHub fine-grained PAT
  /^ghp_[A-Za-z0-9]{20,}/,             // GitHub classic PAT
  /^gho_[A-Za-z0-9]{20,}/,             // GitHub OAuth token
  /^ghs_[A-Za-z0-9]{20,}/,             // GitHub server token
  /^ghu_[A-Za-z0-9]{20,}/,             // GitHub user token
  /^AKIA[0-9A-Z]{16}$/,                // AWS Access Key ID
  /^xox[abprs]-[A-Za-z0-9-]{10,}/,     // Slack tokens
  /^Bearer\s+[A-Za-z0-9._-]{20,}/i,    // explicit bearer header
  /^eyJ[A-Za-z0-9._-]{20,}/,           // JWT (header starts with eyJ)
];

/** Replacement token written in place of redacted values. */
export const REDACTED = "[REDACTED]";

const HIGH_ENTROPY_MIN_LENGTH = 24;

/**
 * Quick-and-dirty entropy estimate (Shannon, bits per char) for short strings.
 * A randomly-generated 32-char API key scores around 4.5+; English prose
 * scores around 3.5-4.0. Combined with a length threshold this catches most
 * opaque credentials without flagging human-written values.
 */
export function approximateEntropyBits(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Decide whether a single primitive value looks like a secret on shape alone.
 * Used both when the key is unknown (top-level scan) and as a backstop when
 * the key didn't trigger but the value looks dangerous.
 */
export function valueLooksSecret(value: unknown): boolean {
  if (typeof value !== "string") return false;
  if (value.length < 12) return false;
  for (const re of SECRET_VALUE_PREFIXES) {
    if (re.test(value)) return true;
  }
  if (
    value.length >= HIGH_ENTROPY_MIN_LENGTH &&
    /^[A-Za-z0-9+/=_.-]+$/.test(value) &&
    approximateEntropyBits(value) >= 4.0
  ) {
    return true;
  }
  return false;
}

function keyLooksSecret(key: string): boolean {
  return SECRET_KEY_PATTERNS.some((re) => re.test(key));
}

/**
 * Walk a value recursively, replacing anything that looks like a secret with
 * the `[REDACTED]` marker. Arrays preserve length, objects preserve keys.
 * Cycles are tolerated by tracking seen objects.
 *
 * The traversal is depth-first and copies on the way back up — callers get a
 * new value safe to JSON.stringify and write to disk; the original input is
 * never mutated.
 */
export function redact<T = unknown>(input: T): T {
  const seen = new WeakMap<object, unknown>();
  return walk(input, /* inSecretContext */ false, seen) as T;
}

function walk(value: unknown, inSecretContext: boolean, seen: WeakMap<object, unknown>): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value === "string") {
    if (inSecretContext) return REDACTED;
    if (valueLooksSecret(value)) return REDACTED;
    return value;
  }
  if (typeof value !== "object") return value;
  if (seen.has(value as object)) return seen.get(value as object);

  if (Array.isArray(value)) {
    const out: unknown[] = [];
    seen.set(value as object, out);
    for (const item of value) {
      out.push(walk(item, inSecretContext, seen));
    }
    return out;
  }

  const obj = value as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  seen.set(value as object, out);
  for (const [k, v] of Object.entries(obj)) {
    const childContext = inSecretContext || keyLooksSecret(k);
    out[k] = walk(v, childContext, seen);
  }
  return out;
}

/**
 * Convenience: redact a value and stringify in deterministic key order. Used
 * by `audit/log.ts` so the hash chain is reproducible across runs.
 */
export function redactAndStringify(input: unknown): string {
  return canonicalJSONStringify(redact(input));
}

/**
 * Canonical JSON: stable key order (sorted alphabetically at every object
 * level). Required for hash chaining — without canonicalization, the same
 * logical entry could hash differently between Node versions or platforms.
 */
export function canonicalJSONStringify(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (value === null || value === undefined) return value;
  if (typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(sortKeys);
  const obj = value as Record<string, unknown>;
  const sorted: Record<string, unknown> = {};
  for (const key of Object.keys(obj).sort()) {
    sorted[key] = sortKeys(obj[key]);
  }
  return sorted;
}
