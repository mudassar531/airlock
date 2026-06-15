/**
 * stdio MCP proxy: spawn a downstream MCP server as a child process and
 * relay newline-delimited JSON-RPC between an upstream client and that
 * child. Every message routes through the configured interceptor.
 *
 * Phase 1 ships pure pass-through. The proxy preserves message ordering,
 * never drops or duplicates messages, and forwards child stderr to its
 * own stderr unchanged so the operator sees downstream diagnostics.
 */

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { randomUUID } from "node:crypto";
import { Readable, Writable } from "node:stream";

import {
  LineFramer,
  serializeMessage,
  type JsonRpcMessage,
} from "./jsonrpc.js";
import {
  identityInterceptor,
  type Interceptor,
  type InterceptorContext,
} from "./interceptor.js";

export interface StdioProxyOptions {
  /** Argv of the downstream server, e.g. `["npx", "-y", "@modelcontextprotocol/server-filesystem", "/tmp"]`. */
  command: string;
  args?: string[];
  env?: NodeJS.ProcessEnv;
  cwd?: string;

  /** Streams for the upstream MCP client. Default: process stdin / stdout / stderr. */
  clientStdin?: Readable;
  clientStdout?: Writable;
  clientStderr?: Writable;

  /** Override the hook applied to every relayed message. Default: identity. */
  interceptor?: Interceptor;

  /** Stable session id; auto-generated when omitted. */
  sessionId?: string;

  /**
   * Called when the proxy starts and the downstream child is spawned.
   * Exposed for tests / hosts that want to await readiness.
   */
  onReady?: (info: { sessionId: string; childPid: number | undefined }) => void;
}

export interface StdioProxyHandle {
  readonly sessionId: string;
  /** PID of the spawned downstream server. */
  readonly childPid: number | undefined;
  /** Resolves with the child's exit code (or null on signal) when the child exits. */
  readonly exited: Promise<number | null>;
  /** Terminate the child and detach. Idempotent. */
  shutdown(signal?: NodeJS.Signals): Promise<void>;
}

/**
 * Start the proxy. The returned handle exposes lifecycle hooks; the proxy
 * itself runs until the child exits or the upstream client closes stdin.
 */
export function startStdioProxy(options: StdioProxyOptions): StdioProxyHandle {
  const sessionId = options.sessionId ?? randomUUID();
  const interceptor: Interceptor = options.interceptor ?? identityInterceptor;
  const clientStdin = options.clientStdin ?? process.stdin;
  const clientStdout = options.clientStdout ?? process.stdout;
  const clientStderr = options.clientStderr ?? process.stderr;

  const child: ChildProcessWithoutNullStreams = spawn(
    options.command,
    options.args ?? [],
    {
      stdio: ["pipe", "pipe", "pipe"],
      env: options.env ?? process.env,
      cwd: options.cwd,
    },
  );

  options.onReady?.({ sessionId, childPid: child.pid });

  let seq = 0;
  const nextSeq = (): number => ++seq;

  const upstreamFramer = new LineFramer();
  const downstreamFramer = new LineFramer();

  // Serialize writes per direction so messages never interleave at the byte
  // level. JSON-RPC ordering matters: a response after a notification must
  // arrive in that order on the wire.
  const upstreamWriteQueue = createSerialWriter(clientStdout);
  const downstreamWriteQueue = createSerialWriter(child.stdin);

  const writeToClient = async (msg: JsonRpcMessage): Promise<void> => {
    await upstreamWriteQueue(serializeMessage(msg));
  };

  const writeToServer = async (msg: JsonRpcMessage): Promise<void> => {
    await downstreamWriteQueue(serializeMessage(msg));
  };

  // Client -> Server: each chunk from stdin is appended to a framer; we drain
  // complete messages, route them through the interceptor, and forward to the
  // child. We process messages strictly in order to preserve JSON-RPC semantics.
  let upstreamProcessing: Promise<void> = Promise.resolve();
  clientStdin.on("data", (chunk: Buffer) => {
    upstreamFramer.append(chunk);
    upstreamProcessing = upstreamProcessing.then(async () => {
      // Pull and process every complete frame currently buffered before
      // returning, so back-to-back messages don't get reordered.
      while (true) {
        let msg: JsonRpcMessage | null;
        try {
          msg = upstreamFramer.readMessage();
        } catch (err) {
          writeStderr(
            clientStderr,
            `airlock: malformed JSON from client, skipping frame: ${(err as Error).message}`,
          );
          continue;
        }
        if (msg === null) return;
        await routeClientToServer(msg);
      }
    });
  });

  // Server -> Client: same shape in reverse.
  let downstreamProcessing: Promise<void> = Promise.resolve();
  child.stdout.on("data", (chunk: Buffer) => {
    downstreamFramer.append(chunk);
    downstreamProcessing = downstreamProcessing.then(async () => {
      while (true) {
        let msg: JsonRpcMessage | null;
        try {
          msg = downstreamFramer.readMessage();
        } catch (err) {
          writeStderr(
            clientStderr,
            `airlock: malformed JSON from server, skipping frame: ${(err as Error).message}`,
          );
          continue;
        }
        if (msg === null) return;
        await routeServerToClient(msg);
      }
    });
  });

  // Pass child's stderr through to ours, line-buffered is fine — it's diagnostic.
  child.stderr.on("data", (chunk: Buffer) => {
    clientStderr.write(chunk);
  });

  const routeClientToServer = async (msg: JsonRpcMessage): Promise<void> => {
    const ctx: InterceptorContext = {
      sessionId,
      direction: "client-to-server",
      seq: nextSeq(),
    };
    let decision;
    try {
      decision = await interceptor(msg, ctx);
    } catch (err) {
      writeStderr(
        clientStderr,
        `airlock: interceptor error (client->server): ${(err as Error).message}`,
      );
      // Fail closed: drop the message rather than forwarding it on error.
      return;
    }
    if (decision.respondToClient) {
      await writeToClient(decision.respondToClient);
    }
    if (decision.forward) {
      await writeToServer(decision.forward);
    }
  };

  const routeServerToClient = async (msg: JsonRpcMessage): Promise<void> => {
    const ctx: InterceptorContext = {
      sessionId,
      direction: "server-to-client",
      seq: nextSeq(),
    };
    let decision;
    try {
      decision = await interceptor(msg, ctx);
    } catch (err) {
      writeStderr(
        clientStderr,
        `airlock: interceptor error (server->client): ${(err as Error).message}`,
      );
      // For server-to-client we still try to forward on error so we don't
      // strand the client waiting forever; but a Phase 4+ deny path will
      // never throw here (it'll short-circuit on the request side instead).
      await writeToClient(msg);
      return;
    }
    if (decision.forward) {
      await writeToClient(decision.forward);
    }
  };

  // Lifecycle: when the client closes stdin, tell the child by closing its
  // stdin too. When the child exits, surface its exit code via the promise.
  const exited = new Promise<number | null>((resolve) => {
    child.on("exit", (code) => {
      // Drain any in-flight processing before resolving.
      Promise.allSettled([upstreamProcessing, downstreamProcessing]).then(() => {
        resolve(code);
      });
    });
  });

  clientStdin.on("end", () => {
    try {
      child.stdin.end();
    } catch {
      // child may already be gone
    }
  });

  let shuttingDown = false;
  const shutdown = async (signal: NodeJS.Signals = "SIGTERM"): Promise<void> => {
    if (shuttingDown) return;
    shuttingDown = true;
    try {
      child.kill(signal);
    } catch {
      // already exited
    }
    await exited;
  };

  return {
    sessionId,
    childPid: child.pid,
    exited,
    shutdown,
  };
}

/**
 * Returns a function that writes Buffers to `out` in strict order, awaiting
 * backpressure (`drain`) when the stream's high-water mark fills.
 */
function createSerialWriter(out: Writable): (buf: Buffer) => Promise<void> {
  let chain: Promise<void> = Promise.resolve();
  return (buf: Buffer) => {
    chain = chain.then(
      () =>
        new Promise<void>((resolve, reject) => {
          const ok = out.write(buf, (err) => {
            if (err) reject(err);
          });
          if (ok) {
            resolve();
          } else {
            out.once("drain", () => resolve());
          }
        }),
    );
    return chain;
  };
}

function writeStderr(stream: Writable, line: string): void {
  try {
    stream.write(line.endsWith("\n") ? line : line + "\n");
  } catch {
    // best-effort diagnostic; nothing to do if stderr is closed
  }
}
