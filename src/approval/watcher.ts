/**
 * Watch the pending-approvals directory for `<id>.resolution` files written
 * by `airlock approve <id>` / `airlock deny <id>`. When one appears, resolve
 * the matching in-memory pending promise via the queue.
 *
 * Uses `fs.watch` with a polling fallback for filesystems that don't deliver
 * events reliably (some network mounts, container layers).
 */

import { watch, type FSWatcher } from "node:fs";
import { readdirSync } from "node:fs";
import type { ApprovalQueue } from "./queue.js";

export interface ResolutionWatcherHandle {
  stop(): void;
}

export function watchPendingResolutions(
  pendingDir: string,
  queue: ApprovalQueue,
): ResolutionWatcherHandle {
  let watcher: FSWatcher | null = null;
  let pollTimer: NodeJS.Timeout | null = null;

  const sweep = (): void => {
    let names: string[] = [];
    try {
      names = readdirSync(pendingDir);
    } catch {
      return;
    }
    for (const name of names) {
      if (name.endsWith(".resolution")) {
        const id = name.slice(0, -".resolution".length);
        queue.resolveFromDisk(id);
      }
    }
  };

  try {
    watcher = watch(pendingDir, { persistent: false }, () => sweep());
  } catch {
    // fs.watch failed; fall back to polling only
  }
  pollTimer = setInterval(sweep, 1_000);
  try {
    pollTimer.unref();
  } catch {
    // not all runtimes
  }
  // Initial sweep in case a resolution arrived before we started watching.
  sweep();

  return {
    stop(): void {
      if (watcher) {
        try {
          watcher.close();
        } catch {
          // best effort
        }
        watcher = null;
      }
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    },
  };
}
