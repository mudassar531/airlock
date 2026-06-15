/**
 * The interceptor is the single hook through which every JSON-RPC message
 * passes on its way through the proxy. Phase 1 ships an identity interceptor
 * (returns the message unchanged) — every later phase extends this seam:
 *
 *   - Phase 2: write an audit entry for each `tools/call`
 *   - Phase 3: classify + score the call, attach the verdict context
 *   - Phase 4: consult the policy engine and yield a verdict
 *   - Phase 5: if verdict is `ask`, hold the call until a human resolves it
 *
 * Keeping this as a single function type means the rest of the proxy never
 * has to grow new hook points. The interceptor decides everything.
 */

import type { JsonRpcMessage } from "./jsonrpc.js";

/**
 * Direction of a relayed message. `client-to-server` flows from the MCP
 * client (e.g. Claude Desktop) downstream to the wrapped server; `server-to-client`
 * flows back upstream.
 */
export type Direction = "client-to-server" | "server-to-client";

/**
 * An interceptor decides what to do with a message in flight. It can:
 *  - return `{ forward: msg }` (possibly modified) to send `msg` to the peer,
 *  - return `{ forward: null }` to drop the message silently (rare; mainly
 *    used when we are short-circuiting a request and have already sent the
 *    synthetic response upstream),
 *  - return `{ forward: null, respondToClient: errorMsg }` to short-circuit a
 *    client-to-server request: send `errorMsg` back to the client and do not
 *    forward to the downstream server. Only valid for `client-to-server`
 *    requests with a JSON-RPC id.
 *
 * Phase 1 always returns `{ forward: msg }` unchanged.
 */
export type InterceptorDecision = {
  forward: JsonRpcMessage | null;
  respondToClient?: JsonRpcMessage;
};

export interface InterceptorContext {
  /** Stable session identifier the proxy assigns on startup. */
  sessionId: string;
  direction: Direction;
  /** Monotonic message sequence number across the session, for logging. */
  seq: number;
}

export type Interceptor = (
  msg: JsonRpcMessage,
  ctx: InterceptorContext,
) => InterceptorDecision | Promise<InterceptorDecision>;

/**
 * The Phase 1 default: pass every message through unchanged. Later phases
 * compose around this — they wrap it, they never replace it.
 */
export const identityInterceptor: Interceptor = (msg) => ({ forward: msg });
