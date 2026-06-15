/**
 * Desktop-notification approval channel. Fires a `node-notifier` ping for
 * every `ask` so the operator notices even when their terminal is hidden.
 *
 * The notification does NOT itself resolve the approval — clicking it just
 * surfaces the request id. Resolution happens via the CLI prompt or
 * `airlock approve <id>` / `airlock deny <id>`.
 *
 * Lazy import for the same reason as `cli.ts`: server-only deployments
 * shouldn't fail to start if the platform doesn't have the native binding.
 */

import type { ApprovalQueue, ApprovalRequestSummary } from "./queue.js";
import { PRODUCT_NAME } from "../constants.js";

export function createNotifyApprovalChannel(opts?: {
  enabled?: () => boolean;
}): (req: ApprovalRequestSummary, queue: ApprovalQueue) => void {
  // Notifications are best-effort and never block; we don't even need a chain.
  const enabled =
    opts?.enabled ?? (() => process.env.AIRLOCK_NO_NOTIFY !== "1");

  return (req, _queue) => {
    void _queue;
    if (!enabled()) return;
    void (async () => {
      try {
        const mod = await import("node-notifier");
        const notifier = (mod as unknown as { default: { notify: (opts: unknown) => void } }).default
          ?? (mod as unknown as { notify: (opts: unknown) => void });
        notifier.notify({
          title: `${PRODUCT_NAME}: approval required`,
          message: `${req.tool} (${req.capability ?? "?"}/${req.operation ?? "?"}, ${req.risk ?? "?"})\nid: ${req.id}\nrun: airlock approve ${req.id}`,
          sound: false,
          wait: false,
        });
      } catch {
        // best effort; notifications are a UX nicety, not a correctness path
      }
    })();
  };
}
