/**
 * Phase 4 interceptor: classify -> trifecta inspect -> risk score -> policy
 * evaluate -> verdict. `allow`/`log` forward; `deny` short-circuits with a
 * structured MCP error and never reaches the downstream server; `ask` is
 * treated as `deny` (with a clear reason) until Phase 5 wires approvals.
 *
 * Pairs requests with responses by id so we can measure end-to-end latency
 * for allowed/logged calls. Denied calls record latency from receipt to the
 * point of denial.
 */

import {
  isJsonRpcRequest,
  isJsonRpcResponse,
  type JsonRpcMessage,
  type JsonRpcErrorResponse,
} from "../proxy/jsonrpc.js";
import type {
  Interceptor,
  InterceptorDecision,
} from "../proxy/interceptor.js";
import { AuditLog } from "./log.js";
import { classify, type Classification } from "../risk/classify.js";
import { TrifectaTracker, type TrifectaSnapshot } from "../risk/trifecta.js";
import { scoreRisk, type RiskAssessment } from "../risk/score.js";
import { evaluate, type Verdict } from "../policy/evaluate.js";
import type { Policy } from "../policy/schema.js";
import { DEFAULT_POLICY } from "../policy/defaults.js";

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
}

export function createAuditingInterceptor(
  opts: AuditingInterceptorOptions,
): Interceptor {
  const { log } = opts;
  const policy = opts.policy ?? DEFAULT_POLICY;
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
      tracker.observe(ctx.sessionId, classification);

      const verdict: Verdict = evaluate(policy, {
        toolName: tool,
        classification,
        trifecta: snapshot,
        assessment,
      });

      // Phase 4: `ask` is not yet wired to a human (that's Phase 5). Per spec:
      // "for now treat as deny with a 'approval not yet wired' reason."
      const effectiveAction = verdict.action === "ask" ? "deny" : verdict.action;

      if (effectiveAction === "deny") {
        const startedAt = Date.now();
        const denialMessage = composeDenialMessage(verdict);
        const errorMsg: JsonRpcErrorResponse = {
          jsonrpc: "2.0",
          id: msg.id,
          error: {
            code: AIRLOCK_DENIED_CODE,
            message: denialMessage,
            data: {
              ruleName: verdict.ruleName,
              capability: classification.capability,
              operation: classification.operation,
              risk: assessment.risk,
              trifecta: snapshot.isLethal,
            },
          },
        };
        log.append({
          sessionId: ctx.sessionId,
          tool,
          capability: classification.capability,
          operation: classification.operation,
          risk: assessment.risk,
          trifecta: snapshot.isLethal,
          args: params?.arguments ?? {},
          verdict: "deny",
          reason: composeReason(verdict, assessment),
          ruleName: verdict.ruleName,
          latencyMs: Date.now() - startedAt,
        });
        return { forward: null, respondToClient: errorMsg };
      }

      // allow or log → forward, and remember to record on the response.
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

function composeDenialMessage(verdict: Verdict): string {
  const note = verdict.note ? ` — ${verdict.note}` : "";
  if (verdict.action === "ask") {
    return `airlock: held for human approval but approval channel not yet wired (rule: ${verdict.ruleName})${note}`;
  }
  return `airlock: denied by rule '${verdict.ruleName}'${note}`;
}

function composeReason(verdict: Verdict, assessment: RiskAssessment): string {
  const askNote =
    verdict.action === "ask"
      ? " [phase-4 placeholder: 'ask' treated as 'deny' until phase 5 approvals]"
      : "";
  return [verdict.reason + askNote, ...assessment.reasons].filter(Boolean).join(" | ");
}
