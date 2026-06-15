/**
 * Phase 3 interceptor: classify every `tools/call`, score risk, track the
 * lethal trifecta per session, and persist all of that into the audit log.
 * Phase 4 will swap the `verdict=allow` placeholder for an actual policy
 * verdict; the per-session trifecta state and risk score are already in
 * place so the policy can match on them.
 *
 * Pairs requests with responses by id so we can measure end-to-end latency.
 * Notifications and non-call requests pass through with no audit entry —
 * the audit log is for *consequential* actions, not chatter.
 */

import {
  isJsonRpcRequest,
  isJsonRpcResponse,
  type JsonRpcMessage,
} from "../proxy/jsonrpc.js";
import type {
  Interceptor,
  InterceptorDecision,
} from "../proxy/interceptor.js";
import { AuditLog } from "./log.js";
import { classify, type Classification } from "../risk/classify.js";
import {
  TrifectaTracker,
  type TrifectaSnapshot,
} from "../risk/trifecta.js";
import { scoreRisk, type RiskAssessment } from "../risk/score.js";

interface PendingCall {
  tool: string;
  args: unknown;
  startedAt: number;
  classification: Classification;
  trifecta: TrifectaSnapshot;
  assessment: RiskAssessment;
}

export interface AuditingInterceptorOptions {
  log: AuditLog;
  /**
   * Optional pre-seeded trifecta tracker. Tests inject one; production code
   * lets the interceptor own its own tracker.
   */
  tracker?: TrifectaTracker;
}

export function createAuditingInterceptor(
  opts: AuditingInterceptorOptions,
): Interceptor {
  const { log } = opts;
  const tracker = opts.tracker ?? new TrifectaTracker();
  const pending = new Map<string, PendingCall>();

  const key = (sessionId: string, id: unknown): string =>
    `${sessionId}:${String(id)}`;

  return (msg: JsonRpcMessage, ctx): InterceptorDecision => {
    if (
      ctx.direction === "client-to-server" &&
      isJsonRpcRequest(msg) &&
      msg.method === "tools/call"
    ) {
      const params = msg.params as
        | { name?: string; arguments?: unknown }
        | undefined;
      const tool = typeof params?.name === "string" ? params.name : "(unknown)";
      const classification = classify(params);
      const snapshot = tracker.inspect(ctx.sessionId, classification);
      const assessment = scoreRisk(classification, snapshot);
      // Observe immediately: the agent has *attempted* this action; trifecta
      // state must reflect that even if a future phase denies the call.
      tracker.observe(ctx.sessionId, classification);

      pending.set(key(ctx.sessionId, msg.id), {
        tool,
        args: params?.arguments ?? {},
        startedAt: Date.now(),
        classification,
        trifecta: snapshot,
        assessment,
      });
    }

    if (ctx.direction === "server-to-client" && isJsonRpcResponse(msg)) {
      const k = key(ctx.sessionId, msg.id);
      const call = pending.get(k);
      if (call) {
        pending.delete(k);
        const verdict = "error" in msg ? "log" : "allow";
        const baseReason =
          "error" in msg
            ? `downstream returned error: ${msg.error.message}`
            : "phase-3 default: allow + record (policy engine in phase 4)";
        const reason = [baseReason, ...call.assessment.reasons]
          .filter(Boolean)
          .join(" | ");
        log.append({
          sessionId: ctx.sessionId,
          tool: call.tool,
          capability: call.classification.capability,
          operation: call.classification.operation,
          risk: call.assessment.risk,
          trifecta: call.trifecta.isLethal,
          args: call.args,
          verdict,
          reason,
          latencyMs: Date.now() - call.startedAt,
        });
      }
    }

    return { forward: msg };
  };
}
