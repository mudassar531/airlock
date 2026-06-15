import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

/**
 * Single source of truth for the product name. Change this constant to rebrand
 * (and update package.json `name` + `bin`); everything user-visible reads it.
 */
export const PRODUCT_NAME = "airlock";

/**
 * Default location for Airlock state on disk. Configurable via AIRLOCK_HOME env var.
 */
export const DEFAULT_HOME_DIR_NAME = `.${PRODUCT_NAME}`;

/**
 * Read the package version from package.json at runtime. tsup bundles the file
 * so we resolve the path relative to the bundled output and walk up to find it.
 * Falls back to "0.0.0-unknown" if it can't be located (defensive; should never happen).
 */
export function getPackageVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    // dist/cli.js -> ../package.json ; src/cli.ts (vitest) -> ../package.json
    for (const candidate of [
      resolve(here, "..", "package.json"),
      resolve(here, "..", "..", "package.json"),
    ]) {
      try {
        const pkg = JSON.parse(readFileSync(candidate, "utf8")) as { version?: string };
        if (pkg.version) return pkg.version;
      } catch {
        // try next candidate
      }
    }
  } catch {
    // fall through
  }
  return "0.0.0-unknown";
}
