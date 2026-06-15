/**
 * Policy loader. Resolution order:
 *
 *   1. `--policy <file>` (explicit) — if specified and not found, error.
 *   2. `./airlock.policy.yaml` in the current working directory.
 *   3. `~/.airlock/policy.yaml`.
 *   4. Built-in `DEFAULT_POLICY` (`src/policy/defaults.ts`).
 *
 * Validation is strict and fail-closed: an invalid policy throws
 * `InvalidPolicyError` and the caller refuses to run rather than silently
 * allowing. Users see exactly which key failed.
 */

import { readFileSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { parse as parseYaml } from "yaml";
import { z } from "zod";

import { PolicySchema, type Policy } from "./schema.js";
import { DEFAULT_POLICY } from "./defaults.js";
import { airlockPaths } from "../config.js";

export type PolicySource = "explicit" | "cwd" | "home" | "default";

export interface LoadedPolicy {
  policy: Policy;
  source: PolicySource;
  /** Filesystem path the policy was loaded from, if any. */
  path?: string;
}

export class InvalidPolicyError extends Error {
  override readonly name = "InvalidPolicyError";
  override readonly cause?: unknown;
  constructor(
    public readonly path: string,
    message: string,
    cause?: unknown,
  ) {
    super(`invalid policy at ${path}: ${message}`);
    if (cause !== undefined) this.cause = cause;
  }
}

export interface LoadPolicyOptions {
  /** Explicit policy path from --policy / API. */
  explicit?: string;
  /** Override the cwd used for the `./airlock.policy.yaml` lookup. */
  cwd?: string;
  /** Override `~/.airlock` for testing. */
  home?: string;
}

export function loadPolicy(opts: LoadPolicyOptions = {}): LoadedPolicy {
  if (opts.explicit) {
    const explicitPath = resolve(opts.explicit);
    if (!existsSync(explicitPath)) {
      throw new InvalidPolicyError(
        explicitPath,
        "file not found (explicit --policy path must exist)",
      );
    }
    return {
      policy: parseAndValidate(explicitPath),
      source: "explicit",
      path: explicitPath,
    };
  }

  const cwd = opts.cwd ?? process.cwd();
  const cwdPath = join(cwd, "airlock.policy.yaml");
  if (existsSync(cwdPath)) {
    return {
      policy: parseAndValidate(cwdPath),
      source: "cwd",
      path: cwdPath,
    };
  }

  const homePaths = airlockPaths(opts.home);
  const homePolicy = join(homePaths.homeDir, "policy.yaml");
  if (existsSync(homePolicy)) {
    return {
      policy: parseAndValidate(homePolicy),
      source: "home",
      path: homePolicy,
    };
  }

  return { policy: DEFAULT_POLICY, source: "default" };
}

function parseAndValidate(path: string): Policy {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw new InvalidPolicyError(path, `cannot read file: ${(err as Error).message}`, err);
  }
  let raw: unknown;
  try {
    raw = parseYaml(text);
  } catch (err) {
    throw new InvalidPolicyError(path, `invalid YAML: ${(err as Error).message}`, err);
  }
  if (raw === null || raw === undefined) {
    throw new InvalidPolicyError(path, "empty policy file");
  }
  const result = PolicySchema.safeParse(raw);
  if (!result.success) {
    throw new InvalidPolicyError(
      path,
      `schema validation failed:\n${formatZodError(result.error)}`,
      result.error,
    );
  }
  // Defense in depth: rule names must be unique so audit + policy-check
  // output isn't ambiguous.
  const seen = new Set<string>();
  for (const rule of result.data.rules) {
    if (seen.has(rule.name)) {
      throw new InvalidPolicyError(path, `duplicate rule name: '${rule.name}'`);
    }
    seen.add(rule.name);
  }
  return result.data;
}

function formatZodError(err: z.ZodError): string {
  return err.issues
    .map((i) => `  - ${i.path.length ? i.path.join(".") : "<root>"}: ${i.message}`)
    .join("\n");
}
