/**
 * JSON-RPC 2.0 message types used by MCP, plus a newline-delimited framer.
 *
 * MCP stdio wire format: one JSON object per line, terminated by `\n`.
 * We frame messages ourselves rather than going through the official SDK's
 * `Client`/`Server` classes because the proxy must be byte-faithful: it
 * forwards exactly what the peer sent, plus a `\n` terminator we know we
 * stripped on the read side.
 *
 * Verified against @modelcontextprotocol/sdk@1.29.0 `shared/stdio.ts`:
 * `ReadBuffer.readMessage` splits on `\n`; `serializeMessage` appends `\n`.
 */

export type JsonRpcId = string | number;

export interface JsonRpcRequest {
  jsonrpc: "2.0";
  id: JsonRpcId;
  method: string;
  params?: unknown;
}

export interface JsonRpcNotification {
  jsonrpc: "2.0";
  method: string;
  params?: unknown;
}

export interface JsonRpcSuccessResponse {
  jsonrpc: "2.0";
  id: JsonRpcId;
  result: unknown;
}

export interface JsonRpcErrorResponse {
  jsonrpc: "2.0";
  id: JsonRpcId | null;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
}

export type JsonRpcMessage =
  | JsonRpcRequest
  | JsonRpcNotification
  | JsonRpcSuccessResponse
  | JsonRpcErrorResponse;

export function isJsonRpcRequest(msg: unknown): msg is JsonRpcRequest {
  if (!msg || typeof msg !== "object") return false;
  const m = msg as Record<string, unknown>;
  return (
    m.jsonrpc === "2.0" &&
    typeof m.method === "string" &&
    (typeof m.id === "string" || typeof m.id === "number")
  );
}

export function isJsonRpcNotification(msg: unknown): msg is JsonRpcNotification {
  if (!msg || typeof msg !== "object") return false;
  const m = msg as Record<string, unknown>;
  return m.jsonrpc === "2.0" && typeof m.method === "string" && !("id" in m);
}

export function isJsonRpcResponse(
  msg: unknown,
): msg is JsonRpcSuccessResponse | JsonRpcErrorResponse {
  if (!msg || typeof msg !== "object") return false;
  const m = msg as Record<string, unknown>;
  if (m.jsonrpc !== "2.0") return false;
  if (!("id" in m)) return false;
  return "result" in m || "error" in m;
}

/**
 * Buffers a stream of bytes and yields one parsed JSON-RPC message per
 * complete line. Mirrors the SDK's ReadBuffer semantics so we round-trip
 * byte-faithfully.
 */
export class LineFramer {
  private buffer: Buffer = Buffer.alloc(0);

  append(chunk: Buffer): void {
    this.buffer =
      this.buffer.length === 0 ? chunk : Buffer.concat([this.buffer, chunk]);
  }

  /**
   * Read the next complete line (without trailing `\n` / `\r\n`) as raw text.
   * Returns null if no complete line is buffered yet.
   */
  readLine(): string | null {
    const idx = this.buffer.indexOf(0x0a /* \n */);
    if (idx === -1) return null;
    const raw = this.buffer.subarray(0, idx);
    this.buffer = this.buffer.subarray(idx + 1);
    if (raw.length > 0 && raw[raw.length - 1] === 0x0d) {
      return raw.subarray(0, raw.length - 1).toString("utf8");
    }
    return raw.toString("utf8");
  }

  /**
   * Parse the next buffered line as a JSON-RPC message. Returns null when no
   * complete line is available. Throws on JSON parse failure so the caller
   * can decide whether to skip the bad frame or shut down.
   */
  readMessage(): JsonRpcMessage | null {
    const line = this.readLine();
    if (line === null) return null;
    if (line.length === 0) return this.readMessage();
    return JSON.parse(line) as JsonRpcMessage;
  }

  pending(): number {
    return this.buffer.length;
  }

  clear(): void {
    this.buffer = Buffer.alloc(0);
  }
}

/**
 * Serialize a JSON-RPC message in MCP wire format: a single JSON line
 * followed by `\n`. Returns a Buffer ready to write to the transport.
 */
export function serializeMessage(msg: JsonRpcMessage): Buffer {
  return Buffer.from(JSON.stringify(msg) + "\n", "utf8");
}
