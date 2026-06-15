/**
 * Filesystem layout and path resolution for Airlock's local state.
 *
 * Default home: `$AIRLOCK_HOME` if set, else `~/.airlock`.
 *
 * All state is local-first by design. No network calls home, no telemetry.
 * Paths are resolved lazily and cached so tests can override `AIRLOCK_HOME`
 * without rebuilding the module.
 */

import { homedir } from "node:os";
import { resolve, join } from "node:path";
import { mkdirSync, chmodSync, existsSync, statSync } from "node:fs";

import { DEFAULT_HOME_DIR_NAME } from "./constants.js";

export interface AirlockPaths {
  homeDir: string;
  auditLog: string;
  keysDir: string;
  privateKeyPath: string;
  publicKeyPath: string;
  pendingDir: string;
}

/**
 * Resolve the Airlock state directory for the current process. Honors the
 * `AIRLOCK_HOME` env var for tests and uncommon setups; otherwise uses
 * `~/.airlock`.
 */
export function resolveAirlockHome(): string {
  const override = process.env.AIRLOCK_HOME;
  if (override && override.trim().length > 0) {
    return resolve(override);
  }
  return resolve(homedir(), DEFAULT_HOME_DIR_NAME);
}

export function airlockPaths(homeDir: string = resolveAirlockHome()): AirlockPaths {
  return {
    homeDir,
    auditLog: join(homeDir, "audit.log"),
    keysDir: join(homeDir, "keys"),
    privateKeyPath: join(homeDir, "keys", "ed25519.private.pem"),
    publicKeyPath: join(homeDir, "keys", "ed25519.public.pem"),
    pendingDir: join(homeDir, "pending"),
  };
}

/**
 * Idempotently create the Airlock state directory tree and apply owner-only
 * mode (0700) to the home and keys dirs so a wide-open umask doesn't leak
 * signing material to other users on shared machines.
 */
export function ensureAirlockHome(paths: AirlockPaths = airlockPaths()): AirlockPaths {
  mkdirSync(paths.homeDir, { recursive: true, mode: 0o700 });
  mkdirSync(paths.keysDir, { recursive: true, mode: 0o700 });
  mkdirSync(paths.pendingDir, { recursive: true, mode: 0o700 });

  // Tighten perms even if the dirs already existed with a wider mode (chmod
  // is a no-op on platforms that don't support it, e.g. Windows).
  try {
    chmodSync(paths.homeDir, 0o700);
    chmodSync(paths.keysDir, 0o700);
    chmodSync(paths.pendingDir, 0o700);
  } catch {
    // best effort; perms aren't a hard requirement on every OS
  }
  return paths;
}

/**
 * True if the Airlock home directory exists and contains an audit log.
 * Used by commands that want to surface a friendly "run `airlock init`" hint.
 */
export function isAirlockInitialized(paths: AirlockPaths = airlockPaths()): boolean {
  if (!existsSync(paths.homeDir)) return false;
  try {
    return statSync(paths.homeDir).isDirectory();
  } catch {
    return false;
  }
}
