/**
 * Phase 5 interceptor: classify -> trifecta -> risk score -> policy ->
 * verdict. Verdicts dispatch as follows:
 *
 *   - allow / log  -> forward; record on the response
 *   - deny         -> short-circuit with a structured MCP error (code -32010)
 *   - ask          -> enqueue an approval, return a `pending` promise so the
 *                     proxy keeps relaying other traffic. When the human
 *                     resolves (approve / deny / timeout), write either the
 *                     original request forward or an MCP error back.
 *
 * Latency for `ask` paths is reported separately: `latencyMs` is the wall
 * time the call spent inside Airlock end-to-end, `waitedMs` is just the
 * time it sat waiting for a human. The audit entry also carries `resolvedBy`
 * (`cli`, `out-of-band`, `timeout`, etc.).
 */

import { redact } from "./redact.js";
import {
  isJsonRpcRequest,
  isJsonRpcResponse,
  type JsonRpcMessage,
  type JsonRpcErrorResponse,
  type JsonRpcRequest,
} from "../proxy/jsonrpc.js";
import type {
  Interceptor,
  InterceptorDecision,
  InterceptorResolution,
} from "../proxy/interceptor.js";
import { AuditLog } from "./log.js";
import { classify, type Classification } from "../risk/classify.js";
import { TrifectaTracker, type TrifectaSnapshot } from "../risk/trifecta.js";
import { scoreRisk, type RiskAssessment } from "../risk/score.js";
import { evaluate, type Verdict } from "../policy/evaluate.js";
import type { Policy } from "../policy/schema.js";
import { DEFAULT_POLICY } from "../policy/defaults.js";
import type { ApprovalQueue } from "../approval/queue.js";

/**
 * Implementation-defined JSON-RPC error code reserved for Airlock denials.
 * Stays in the `-32000..-32099` server-error range per the spec.
 */
export const AIRLOCK_DENIED_CODE = -32010;

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
  /** Active policy. Defaults to the built-in default pack. */
  policy?: Policy;
  /** Optional pre-seeded trifecta tracker (used in tests). */
  tracker?: TrifectaTracker;
  /**
   * Approval queue used for `ask` verdicts. Required if the active policy
   * can yield an `ask` (i.e. always, in practice). If omitted, `ask` falls
   * back to `deny` with a clear reason in the audit log — same as Phase 4.
   */
  approvals?: ApprovalQueue;
}

export function createAuditingInterceptor(
  opts: AuditingInterceptorOptions,
): Interceptor {
  const { log, approvals } = opts;
  const policy = opts.policy ?? DEFAULT_POLICY;
  const tracker = opts.tracker ?? new TrifectaTracker();
  const pending = new Map<string, PendingCall>();

  const key = (sessionId: string, id: unknown): string =>
    `${sessionId}:${String(id)}`;

  return async (msg: JsonRpcMessage, ctx): Promise<InterceptorDecision> => {
    if (
      ctx.direction === "client-to-server" &&
      isJsonRpcRequest(msg) &&
      msg.method === "tools/call"
    ) {
      const params = msg.params as
        | { name?: string; arguments?: unknown }
        | undefined;
      const tool = typeof params?.name === "string" ? params.name : "(unknown)";
      const args = params?.arguments ?? {};
      const classification = classify(params);
      const snapshot = tracker.inspect(ctx.sessionId, classification);
      const assessment = scoreRisk(classification, snapshot);
      tracker.observe(ctx.sessionId, classification);

      const verdict: Verdict = evaluate(policy, {
        toolName: tool,
        classification,
        trifecta: snapshot,
        assessment,
      });
      const startedAt = Date.now();

      if (verdict.action === "deny") {
        const errorMsg = buildDenialError(msg.id, verdict, classification, assessment, snapshot);
        log.append({
          sessionId: ctx.sessionId,
          tool,
          capability: classification.capability,
          operation: classification.operation,
          risk: assessment.risk,
          trifecta: snapshot.isLethal,
          args,
          verdict: "deny",
          reason: composeReason(verdict, assessment),
          ruleName: verdict.ruleName,
          latencyMs: Date.now() - startedAt,
        });
        return { forward: null, respondToClient: errorMsg };
      }

      if (verdict.action === "ask") {
        if (!approvals) {
          // No approval channel wired: behave as Phase 4 — synthesize a deny.
          const errorMsg = buildDenialError(
            msg.id,
            { ...verdict, action: "ask" },
            classification,
            assessment,
            snapshot,
            "approval channel not configured",
          );
          log.append({
            sessionId: ctx.sessionId,
            tool,
            capability: classification.capability,
            operation: classification.operation,
            risk: assessment.risk,
            trifecta: snapshot.isLethal,
            args,
            verdict: "deny",
            reason: composeReason(verdict, assessment) + " | approval channel not configured",
            ruleName: verdict.ruleName,
            latencyMs: Date.now() - startedAt,
          });
          return { forward: null, respondToClient: errorMsg };
        }

        const { promise } = approvals.enqueue({
          sessionId: ctx.sessionId,
          tool,
          capability: classification.capability,
          operation: classification.operation,
          risk: assessment.risk,
          trifecta: snapshot.isLethal,
          argsRedacted: redact(args),
          ruleName: verdict.ruleName,
          reason: composeReason(verdict, assessment),
        });

        // Return a `pending` decision: forward nothing right now, hand the
        // proxy a promise that resolves with either the original request to
        // forward (approve) or an MCP error to send to the client (deny /
        // timeout). The proxy advances the upstream chain immediately so
        // other messages keep flowing.
        const pendingResolution: Promise<InterceptorResolution> = promise.then(
          (resolved) => {
            const isApprove = resolved.resolution === "approve";
            const reasonBase = isApprove
              ? `approved by ${resolved.resolvedBy} after ${resolved.waitedMs}ms`
              : resolved.resolution === "timeout"
                ? `denied: human approval timed out after ${resolved.waitedMs}ms`
                : `denied by ${resolved.resolvedBy} after ${resolved.waitedMs}ms`;
            log.append({
              sessionId: ctx.sessionId,
              tool,
              capability: classification.capability,
              operation: classification.operation,
              risk: assessment.risk,
              trifecta: snapshot.isLethal,
              args,
              verdict: isApprove ? "allow" : "deny",
              reason: [reasonBase, composeReason(verdict, assessment)]
                .filter(Boolean)
                .join(" | "),
              ruleName: verdict.ruleName,
              latencyMs: Date.now() - startedAt,
              resolvedBy: resolved.resolvedBy,
              waitedMs: resolved.waitedMs,
            });
            if (isApprove) {
              // Forward the *original* request now that the human approved.
              return { forward: msg as JsonRpcRequest, respondToClient: undefined };
            }
            const errorMsg = buildDenialError(
              msg.id,
              { ...verdict, action: resolved.resolution === "timeout" ? "deny" : "ask" },
              classification,
              assessment,
              snapshot,
              resolved.resolution === "timeout" ? "human approval timed out" : `denied by ${resolved.resolvedBy}`,
            );
            return { forward: null, respondToClient: errorMsg };
          },
        );

        // Track the call's id so the response-side handler still records the
        // downstream's actual result (or error) when it eventually arrives —
        // but only AFTER approval. Defer registration until the pending
        // resolves with `approve`.
        pendingResolution.then((res) => {
          if (res.forward) {
            pending.set(key(ctx.sessionId, msg.id), {
              tool,
              args,
              startedAt: Date.now(),
              classification,
              trifecta: snapshot,
              assessment,
            });
          }
        });

        return { forward: null, pending: pendingResolution };
      }

      // allow or log → forward, and remember to record on the response.
      pending.set(key(ctx.sessionId, msg.id), {
        tool,
        args,
        startedAt,
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
        const downstreamErrored = "error" in msg;
        const verdict = downstreamErrored ? "log" : "allow";
        const baseReason = downstreamErrored
          ? `downstream returned error: ${msg.error.message}`
          : "policy: forwarded";
        log.append({
          sessionId: ctx.sessionId,
          tool: call.tool,
          capability: call.classification.capability,
          operation: call.classification.operation,
          risk: call.assessment.risk,
          trifecta: call.trifecta.isLethal,
          args: call.args,
          verdict,
          reason: [baseReason, ...call.assessment.reasons].filter(Boolean).join(" | "),
          latencyMs: Date.now() - call.startedAt,
        });
      }
    }

    return { forward: msg };
  };
}

function buildDenialError(
  id: string | number,
  verdict: Verdict,
  classification: Classification,
  assessment: RiskAssessment,
  trifecta: TrifectaSnapshot,
  extraNote?: string,
): JsonRpcErrorResponse {
  const note = verdict.note ? ` — ${verdict.note}` : "";
  const extra = extraNote ? ` (${extraNote})` : "";
  const message =
    verdict.action === "ask"
      ? `airlock: held for human approval${extra} (rule: ${verdict.ruleName})${note}`
      : `airlock: denied by rule '${verdict.ruleName}'${extra}${note}`;
  return {
    jsonrpc: "2.0",
    id,
    error: {
      code: AIRLOCK_DENIED_CODE,
      message,
      data: {
        ruleName: verdict.ruleName,
        capability: classification.capability,
        operation: classification.operation,
        risk: assessment.risk,
        trifecta: trifecta.isLethal,
      },
    },
  };
}

function composeReason(verdict: Verdict, assessment: RiskAssessment): string {
  return [verdict.reason, ...assessment.reasons].filter(Boolean).join(" | ");
}
