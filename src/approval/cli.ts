/**
 * Interactive CLI approval prompt. When `wrap`'s stdout is a TTY (so the
 * operator is watching), present an `@inquirer/prompts` confirm for each
 * `ask` verdict showing the tool, redacted args, capability/operation,
 * risk, and reasons. Approve / deny resolves the queued approval.
 *
 * The prompt runs against `process.stderr` so it doesn't corrupt the
 * stdio JSON-RPC stream on stdout. Only one prompt is active at a time —
 * concurrent asks queue up serially in the prompt loop while the proxy's
 * non-blocking pending channel keeps other traffic flowing.
 */

import type { ApprovalQueue, ApprovalRequestSummary } from "./queue.js";

/**
 * Wire the queue's `onEnqueue` to the inquirer prompt. Returns the handler.
 * Constructed as a function so tests can swap it for a programmatic
 * resolver without pulling in the inquirer dependency.
 *
 * The actual `@inquirer/prompts` import is lazy so server-only deployments
 * (no TTY) can ship without it being required.
 */
export function createCliApprovalChannel(opts?: {
  enabled?: () => boolean;
}): (req: ApprovalRequestSummary, queue: ApprovalQueue) => void {
  const enabled = opts?.enabled ?? (() => process.stderr.isTTY === true);
  // Promise chain so only one inquirer prompt runs at a time.
  let chain: Promise<void> = Promise.resolve();

  return (req, queue) => {
    if (!enabled()) return;
    chain = chain.then(async () => {
      try {
        const { confirm } = (await import("@inquirer/prompts")) as {
          confirm: (opts: { message: string; default?: boolean }) => Promise<boolean>;
        };
        const lines = [
          "",
          `── airlock approval required ─────────────────────────────────`,
          `  id:           ${req.id}`,
          `  session:      ${req.sessionId}`,
          `  tool:         ${req.tool}`,
          `  capability:   ${req.capability ?? "?"}/${req.operation ?? "?"}`,
          `  risk:         ${req.risk ?? "?"}${req.trifecta ? " (TRIFECTA)" : ""}`,
          `  rule:         ${req.ruleName ?? "?"}`,
          `  reason:       ${req.reason}`,
          `  args:         ${truncate(JSON.stringify(req.argsRedacted))}`,
        ];
        for (const l of lines) process.stderr.write(l + "\n");
        const approved = await confirm({
          message: "approve this call?",
          default: false,
        });
        // It's possible the approval was already resolved (timeout, out-of-band)
        // by the time the user answered; `resolve()` returns false in that case
        // and we ignore it.
        queue.resolve(req.id, approved ? "approve" : "deny", "cli");
      } catch {
        // user hit ^C or prompt failed; safest to deny
        queue.resolve(req.id, "deny", "cli:aborted");
      }
    });
  };
}

function truncate(s: string, max: number = 200): string {
  return s.length > max ? s.slice(0, max - 3) + "..." : s;
}
