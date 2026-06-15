/**
 * Streamable HTTP transport for the Airlock proxy.
 *
 * The current MCP remote transport (Streamable HTTP) replaces the older
 * SSE transport: clients POST JSON-RPC messages to a single endpoint
 * (default `/mcp`), and may issue a GET to that same endpoint to open an
 * SSE stream for server-initiated notifications. This module wraps the
 * existing stdio downstream child so a single Airlock instance can speak
 * either stdio (default) or HTTP without re-implementing the policy /
 * audit / approval pipeline.
 *
 * Security:
 *   - Bound to 127.0.0.1 by default. DNS rebinding is prevented by
 *     validating the `Origin` header against an allow-list (defaults to
 *     a localhost-only set) per the MCP transport security guidance.
 *   - Only POST and GET on the configured path are honored; everything
 *     else is `404 Not Found`.
 *
 * Scope: Phase 6 ships a minimal POST-only relay sufficient for the
 * Verification Gate (a `tools/call` round-trips and a disallowed Origin
 * is rejected). Full SSE notification streaming is left for a follow-up;
 * the spec calls out "minimal" implementation explicitly.
 */

import http from "node:http";
import { randomUUID } from "node:crypto";
import type { AddressInfo } from "node:net";
import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";

import {
  LineFramer,
  serializeMessage,
  type JsonRpcMessage,
  isJsonRpcResponse,
  type JsonRpcId,
} from "./jsonrpc.js";
import {
  identityInterceptor,
  type Interceptor,
  type InterceptorContext,
} from "./interceptor.js";

export interface HttpProxyOptions {
  /** Downstream stdio MCP server argv. */
  command: string;
  args?: string[];
  env?: NodeJS.ProcessEnv;
  cwd?: string;

  /** HTTP listen settings. */
  port?: number;
  host?: string;
  /** Single endpoint path. Default `/mcp`. */
  path?: string;

  /**
   * Allowed `Origin` header values. Use `"*"` to disable origin checks
   * (NOT recommended). Defaults to a localhost allow-list. The check is
   * exact-match on `Origin`; absence of an `Origin` header on POST is
   * allowed (e.g. curl / native fetches), since DNS rebinding requires
   * a browser context that always sets `Origin`.
   */
  allowedOrigins?: string[] | "*";

  interceptor?: Interceptor;
  sessionId?: string;
  onReady?: (info: { sessionId: string; childPid: number | undefined; address: AddressInfo }) => void;
}

export interface HttpProxyHandle {
  readonly sessionId: string;
  readonly childPid: number | undefined;
  readonly address: AddressInfo;
  shutdown(): Promise<void>;
}

const DEFAULT_LOCALHOST_ORIGINS = [
  "http://localhost",
  "http://127.0.0.1",
  "http://[::1]",
  // Common dev ports — Origin includes the port if non-default.
  ...[3000, 5173, 8080, 8000, 9000].flatMap((p) => [
    `http://localhost:${p}`,
    `http://127.0.0.1:${p}`,
  ]),
];

export async function startHttpProxy(opts: HttpProxyOptions): Promise<HttpProxyHandle> {
  const sessionId = opts.sessionId ?? randomUUID();
  const interceptor = opts.interceptor ?? identityInterceptor;
  const path = opts.path ?? "/mcp";
  const host = opts.host ?? "127.0.0.1";
  const allowedOrigins = opts.allowedOrigins ?? DEFAULT_LOCALHOST_ORIGINS;

  // Spawn the downstream stdio server. We reuse stdio framing for the link
  // between Airlock and the child; HTTP is only on the client-facing side.
  const child: ChildProcessWithoutNullStreams = spawn(
    opts.command,
    opts.args ?? [],
    {
      stdio: ["pipe", "pipe", "pipe"],
      env: opts.env ?? process.env,
      cwd: opts.cwd,
    },
  );

  // Route responses back to the originating HTTP request by JSON-RPC id.
  const downstreamFramer = new LineFramer();
  const responseWaiters = new Map<string, (msg: JsonRpcMessage) => void>();
  const responseKey = (id: JsonRpcId | null): string => String(id);

  child.stdout.on("data", (chunk: Buffer) => {
    downstreamFramer.append(chunk);
    while (true) {
      let msg: JsonRpcMessage | null;
      try {
        msg = downstreamFramer.readMessage();
      } catch {
        continue;
      }
      if (msg === null) return;
      if (isJsonRpcResponse(msg)) {
        const k = responseKey(msg.id);
        const waiter = responseWaiters.get(k);
        if (waiter) {
          responseWaiters.delete(k);
          waiter(msg);
        }
      }
      // notifications/server requests are discarded in this minimal POST-only
      // transport — SSE-stream streaming for them is the follow-up.
    }
  });
  child.stderr.on("data", (chunk: Buffer) => process.stderr.write(chunk));

  let seq = 0;
  const nextSeq = (): number => ++seq;

  const writeToChild = async (msg: JsonRpcMessage): Promise<void> => {
    await new Promise<void>((resolve, reject) => {
      const ok = child.stdin.write(serializeMessage(msg), (err) =>
        err ? reject(err) : resolve(),
      );
      if (!ok) child.stdin.once("drain", () => resolve());
    });
  };

  const handleClientMessage = async (msg: JsonRpcMessage): Promise<JsonRpcMessage | null> => {
    const ctx: InterceptorContext = {
      sessionId,
      direction: "client-to-server",
      seq: nextSeq(),
    };
    const decision = await interceptor(msg, ctx);
    if (decision.respondToClient) return decision.respondToClient;
    if (!decision.forward) {
      // Held async (pending) or dropped — for HTTP we must produce a
      // response now. Await the pending resolution if present.
      if (decision.pending) {
        const resolution = await decision.pending;
        if (resolution.respondToClient) return resolution.respondToClient;
        if (resolution.forward) {
          return forwardAndAwaitResponse(resolution.forward);
        }
      }
      return null;
    }
    return forwardAndAwaitResponse(decision.forward);
  };

  const forwardAndAwaitResponse = async (
    msg: JsonRpcMessage,
  ): Promise<JsonRpcMessage | null> => {
    if (!("id" in msg) || msg.id === undefined) {
      // notification — fire-and-forget
      await writeToChild(msg);
      return null;
    }
    const k = responseKey((msg as { id: JsonRpcId }).id);
    const responsePromise = new Promise<JsonRpcMessage>((resolve) => {
      responseWaiters.set(k, resolve);
    });
    await writeToChild(msg);
    return responsePromise;
  };

  const server = http.createServer(async (req, res) => {
    if (req.method === "GET" && req.url === path) {
      // SSE stream stub: respond 200 with an empty event-stream so basic
      // clients don't error. Full SSE delivery is future work.
      res.writeHead(200, {
        "content-type": "text/event-stream",
        "cache-control": "no-cache",
        connection: "keep-alive",
      });
      // Keep open; the client may close on its own.
      return;
    }
    if (req.method !== "POST" || req.url !== path) {
      res.writeHead(404, { "content-type": "text/plain" });
      res.end("not found");
      return;
    }

    // Origin validation (DNS rebinding mitigation).
    if (allowedOrigins !== "*") {
      const origin = req.headers.origin;
      if (origin !== undefined) {
        const ok = allowedOrigins.some((allow) => allow === origin);
        if (!ok) {
          res.writeHead(403, { "content-type": "application/json" });
          res.end(
            JSON.stringify({
              jsonrpc: "2.0",
              id: null,
              error: {
                code: -32099,
                message: `airlock: disallowed Origin '${origin}'`,
              },
            }),
          );
          return;
        }
      }
    }

    // Read body
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      let body: string;
      try {
        body = Buffer.concat(chunks).toString("utf8");
      } catch {
        respondError(res, null, -32700, "could not read body");
        return;
      }
      let msg: JsonRpcMessage;
      try {
        msg = JSON.parse(body) as JsonRpcMessage;
      } catch (err) {
        respondError(res, null, -32700, `parse error: ${(err as Error).message}`);
        return;
      }
      try {
        const response = await handleClientMessage(msg);
        if (response === null) {
          res.writeHead(204);
          res.end();
          return;
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify(response));
      } catch (err) {
        respondError(res, "id" in msg ? msg.id : null, -32603, `internal: ${(err as Error).message}`);
      }
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port ?? 0, host, () => {
      server.off("error", reject);
      resolve();
    });
  });

  const address = server.address() as AddressInfo;
  opts.onReady?.({ sessionId, childPid: child.pid, address });

  return {
    sessionId,
    childPid: child.pid,
    address,
    shutdown: async () => {
      await new Promise<void>((resolve) => server.close(() => resolve()));
      try {
        child.kill("SIGTERM");
      } catch {
        // already exited
      }
    },
  };
}

function respondError(
  res: http.ServerResponse,
  id: JsonRpcId | null | undefined,
  code: number,
  message: string,
): void {
  res.writeHead(400, { "content-type": "application/json" });
  res.end(
    JSON.stringify({
      jsonrpc: "2.0",
      id: id ?? null,
      error: { code, message },
    }),
  );
}
