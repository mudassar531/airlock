/**
 * Per-session lethal-trifecta tracker.
 *
 * Within a single MCP session, mark three flags as the agent does work:
 *
 *   - readPrivate:  any read of local/private data (filesystem read, secret read,
 *                   personal email/notes read).
 *   - sawUntrusted: any read that pulled external/untrusted content (web fetch,
 *                   email body, fetched document).
 *   - outbound:     about to perform an outbound action (network send, message
 *                   send, payment spend).
 *
 * When a call's classification + the prior session state imply all three would
 * be true at the moment of the action, we have the lethal trifecta — the
 * structural shape of "exfiltrate private data via prompt injection." The
 * policy engine's default `hold-the-lethal-trifecta` rule asks for human
 * approval in that case.
 *
 * State is per-`sessionId`. The proxy generates one session id per `wrap`
 * invocation, so this naturally scopes to a single agent run.
 *
 * Tracker is intentionally cheap and lock-free: an in-memory Map. If a host
 * runs multiple proxies, each has its own tracker — that's correct, because
 * sessions don't cross processes.
 */

import type { Capability, Classification, Operation } from "./classify.js";

export interface TrifectaState {
  readPrivate: boolean;
  sawUntrusted: boolean;
  /** Set true when an outbound was *attempted* (regardless of verdict). */
  outboundAttempted: boolean;
}

export interface TrifectaSnapshot extends TrifectaState {
  /** True iff `current` would complete the trifecta when applied to the state. */
  isLethal: boolean;
  /** Plain-English reasons backing the lethal flag (empty if not lethal). */
  reasons: string[];
}

const PRIVATE_READ_CAPABILITIES: Capability[] = ["filesystem", "secret", "message"];

/** Whether `c` represents an outbound action that would exfiltrate. */
export function isOutboundCall(
  capability: Capability,
  operation: Operation,
): boolean {
  if (capability === "network" && (operation === "send" || operation === "write" || operation === "delete")) {
    return true;
  }
  if (capability === "message" && operation === "send") return true;
  if (capability === "payment" && operation === "spend") return true;
  return false;
}

/** Whether the call represents a read of *private/local* data.
 *
 * Note: a single read can be BOTH private AND ingest untrusted content
 * (a user's personal email/notes is private, but its body is untrusted
 * because it can carry an injected instruction). The two flags are
 * independent — we don't suppress `readPrivate` when `untrustedRead`
 * is also true.
 */
export function isPrivateRead(
  capability: Capability,
  operation: Operation,
  _untrustedRead: boolean | undefined,
): boolean {
  void _untrustedRead;
  if (operation !== "read") return false;
  return PRIVATE_READ_CAPABILITIES.includes(capability);
}

export class TrifectaTracker {
  private states = new Map<string, TrifectaState>();

  /** Read-only view of session state. Returns a zeroed state if unseen. */
  state(sessionId: string): TrifectaState {
    return (
      this.states.get(sessionId) ?? {
        readPrivate: false,
        sawUntrusted: false,
        outboundAttempted: false,
      }
    );
  }

  /**
   * Inspect the current call against the prior session state and return a
   * snapshot indicating whether applying this call would complete the trifecta.
   * Does NOT mutate state — call `observe` after the policy decides to
   * record that this attempt happened.
   */
  inspect(sessionId: string, c: Classification): TrifectaSnapshot {
    const prior = this.state(sessionId);
    const willBeOutbound = isOutboundCall(c.capability, c.operation);

    const willReadPrivate =
      prior.readPrivate || isPrivateRead(c.capability, c.operation, c.untrustedRead);
    const willSawUntrusted =
      prior.sawUntrusted || (c.operation === "read" && c.untrustedRead === true);

    const reasons: string[] = [];
    const isLethal = willReadPrivate && willSawUntrusted && willBeOutbound;
    if (isLethal) {
      if (prior.readPrivate) reasons.push("session previously read private/local data");
      else if (isPrivateRead(c.capability, c.operation, c.untrustedRead))
        reasons.push("this call reads private/local data");
      if (prior.sawUntrusted)
        reasons.push("session previously ingested external/untrusted content");
      else if (c.operation === "read" && c.untrustedRead)
        reasons.push("this call ingests external/untrusted content");
      reasons.push(
        "this call is an outbound action (network send / message / payment)",
      );
    }

    return {
      ...prior,
      isLethal,
      reasons,
    };
  }

  /**
   * Record that this call happened. Always observed after the verdict —
   * `ask` and `deny` paths still update state because the *agent attempted*
   * the action; the trifecta is about agent capability, not outcome.
   */
  observe(sessionId: string, c: Classification): void {
    const prior = this.state(sessionId);
    const next: TrifectaState = {
      readPrivate:
        prior.readPrivate ||
        isPrivateRead(c.capability, c.operation, c.untrustedRead),
      sawUntrusted:
        prior.sawUntrusted || (c.operation === "read" && c.untrustedRead === true),
      outboundAttempted:
        prior.outboundAttempted || isOutboundCall(c.capability, c.operation),
    };
    this.states.set(sessionId, next);
  }

  /** Reset a session's state, e.g. when the client reconnects with a fresh id. */
  reset(sessionId: string): void {
    this.states.delete(sessionId);
  }

  /** Test helper: clear all sessions. */
  clear(): void {
    this.states.clear();
  }
}
