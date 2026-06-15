/**
 * Phase 2 interceptor: log every `tools/call` request to the audit log
 * with verdict=allow. Phases 3-5 will replace this with classify -> score
 * -> policy -> approve and the verdict will reflect the actual decision.
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

interface PendingCall {
  tool: string;
  args: unknown;
  startedAt: number;
}

export interface AuditingInterceptorOptions {
  /** Audit log instance to write into. Construct one for the proxy session. */
  log: AuditLog;
}

export function createAuditingInterceptor(opts: AuditingInterceptorOptions): Interceptor {
  const { log } = opts;
  const pending = new Map<string, PendingCall>();

  const key = (sessionId: string, id: unknown): string => `${sessionId}:${String(id)}`;

  return (msg: JsonRpcMessage, ctx): InterceptorDecision => {
    if (ctx.direction === "client-to-server" && isJsonRpcRequest(msg) && msg.method === "tools/call") {
      const params = msg.params as { name?: string; arguments?: unknown } | undefined;
      const tool = typeof params?.name === "string" ? params.name : "(unknown)";
      pending.set(key(ctx.sessionId, msg.id), {
        tool,
        args: params?.arguments ?? {},
        startedAt: Date.now(),
      });
    }

    if (ctx.direction === "server-to-client" && isJsonRpcResponse(msg)) {
      const k = key(ctx.sessionId, msg.id);
      const call = pending.get(k);
      if (call) {
        pending.delete(k);
        const verdict = "error" in msg ? "log" : "allow";
        const reason =
          "error" in msg
            ? `downstream returned error: ${msg.error.message}`
            : "phase-2 default: allow + record";
        log.append({
          sessionId: ctx.sessionId,
          tool: call.tool,
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
