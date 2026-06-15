/**
 * Classify a `tools/call` into a `(capability, operation)` pair.
 *
 * "Capability" is *what kind of thing the action touches* — the filesystem,
 * the shell, the network, etc. "Operation" is *what it does* — read, write,
 * execute, send, spend. Together they're the unit the policy engine matches
 * against.
 *
 * Classification is best-effort and conservative. When uncertain we return
 * `("other", "other")`; the policy engine's `on_unmatched` rule then decides
 * (the default is `ask`, which is fail-closed).
 *
 * Three signals are combined:
 *   1. An explicit tool-name → capability map. We ship a built-in map for
 *      common MCP servers (filesystem, fetch, shell, git, slack, ...).
 *   2. Convention-driven heuristics on the tool name (prefix/suffix words
 *      like `read_`, `delete_`, `_send`, `_pay`).
 *   3. Argument shape heuristics (URL → network, path → filesystem,
 *      to/recipient → message, amount/currency → payment).
 *
 * The classifier is pure: same input → same output, no IO, no clock.
 */

export type Capability =
  | "filesystem"
  | "shell"
  | "network"
  | "message"
  | "payment"
  | "secret"
  | "other";

export type Operation =
  | "read"
  | "write"
  | "delete"
  | "execute"
  | "send"
  | "spend"
  | "other";

export interface Classification {
  capability: Capability;
  operation: Operation;
  /**
   * Whether the read/fetch is pulling content from an *external/untrusted*
   * source (a web URL, an inbox, a fetched document). Important for trifecta
   * detection: only untrusted reads light up `sawUntrusted`.
   */
  untrustedRead?: boolean;
  /** Human-readable explanation of *why* we classified this way. */
  signals: string[];
}

/**
 * Built-in tool-name → capability+operation map. Populated from the most
 * common MCP servers in the wild (filesystem, fetch, brave-search, github,
 * slack, postgres, time, etc.). Lowercase keys; lookup is case-insensitive.
 *
 * Entries here win over heuristics; they're the high-confidence path.
 */
const TOOL_MAP: Record<
  string,
  { capability: Capability; operation: Operation; untrustedRead?: boolean }
> = {
  // @modelcontextprotocol/server-filesystem
  read_file: { capability: "filesystem", operation: "read" },
  read_multiple_files: { capability: "filesystem", operation: "read" },
  write_file: { capability: "filesystem", operation: "write" },
  edit_file: { capability: "filesystem", operation: "write" },
  create_directory: { capability: "filesystem", operation: "write" },
  list_directory: { capability: "filesystem", operation: "read" },
  directory_tree: { capability: "filesystem", operation: "read" },
  move_file: { capability: "filesystem", operation: "write" },
  search_files: { capability: "filesystem", operation: "read" },
  get_file_info: { capability: "filesystem", operation: "read" },
  delete_file: { capability: "filesystem", operation: "delete" },

  // @modelcontextprotocol/server-fetch (and similar HTTP-fetch tools)
  fetch: { capability: "network", operation: "read", untrustedRead: true },
  http_get: { capability: "network", operation: "read", untrustedRead: true },
  http_post: { capability: "network", operation: "send" },
  http_put: { capability: "network", operation: "send" },
  http_delete: { capability: "network", operation: "delete" },

  // brave-search / search tools — pulls untrusted external content
  brave_web_search: { capability: "network", operation: "read", untrustedRead: true },
  brave_local_search: { capability: "network", operation: "read", untrustedRead: true },
  web_search: { capability: "network", operation: "read", untrustedRead: true },

  // shell servers
  shell_exec: { capability: "shell", operation: "execute" },
  execute_command: { capability: "shell", operation: "execute" },
  run_command: { capability: "shell", operation: "execute" },
  bash: { capability: "shell", operation: "execute" },

  // git
  git_status: { capability: "filesystem", operation: "read" },
  git_diff: { capability: "filesystem", operation: "read" },
  git_log: { capability: "filesystem", operation: "read" },
  git_push: { capability: "network", operation: "send" },
  git_commit: { capability: "filesystem", operation: "write" },

  // messaging
  send_email: { capability: "message", operation: "send" },
  send_message: { capability: "message", operation: "send" },
  slack_post_message: { capability: "message", operation: "send" },
  slack_send_message: { capability: "message", operation: "send" },
  telegram_send_message: { capability: "message", operation: "send" },

  // payments
  charge: { capability: "payment", operation: "spend" },
  pay: { capability: "payment", operation: "spend" },
  transfer: { capability: "payment", operation: "spend" },
  stripe_create_charge: { capability: "payment", operation: "spend" },

  // secret stores (read = exfil-relevant)
  vault_read: { capability: "secret", operation: "read" },
  get_secret: { capability: "secret", operation: "read" },
  read_secret: { capability: "secret", operation: "read" },

  // common "load notes/email/doc" patterns — treat as untrusted reads
  read_notes: { capability: "filesystem", operation: "read", untrustedRead: true },
  read_email: { capability: "message", operation: "read", untrustedRead: true },
  read_inbox: { capability: "message", operation: "read", untrustedRead: true },
  fetch_document: { capability: "network", operation: "read", untrustedRead: true },
};

interface ToolCallParams {
  name?: string;
  arguments?: unknown;
}

/**
 * Classify a single `tools/call`. `name` is the tool name (e.g. "read_file")
 * and `args` is the `arguments` object the agent supplied.
 */
export function classify(params: ToolCallParams | undefined): Classification {
  const name = (params?.name ?? "").toLowerCase().trim();
  const args = (params?.arguments ?? {}) as Record<string, unknown>;
  const signals: string[] = [];

  // 1. Explicit map: high-confidence overrides.
  const mapped = TOOL_MAP[name];
  if (mapped) {
    signals.push(`tool name '${name}' is in the built-in capability map`);
    const out: Classification = {
      capability: mapped.capability,
      operation: mapped.operation,
      signals,
    };
    if (mapped.untrustedRead) out.untrustedRead = true;
    // Argument shape can still upgrade an untrusted-read signal we missed.
    if (out.operation === "read" && argsLookExternal(args)) {
      out.untrustedRead = true;
      signals.push("argument shape suggests external/untrusted content");
    }
    return out;
  }

  // 2. Name heuristics.
  const nameSignal = classifyByName(name, signals);
  // 3. Argument shape.
  const shapeSignal = classifyByArgs(args, signals);

  // Combine. Argument-shape capability wins ties (it's more concrete than
  // a generic verb in the name); name-derived operation wins ties (the
  // verb is usually clearer than the args).
  let capability: Capability =
    shapeSignal?.capability ?? nameSignal?.capability ?? "other";
  let operation: Operation = nameSignal?.operation ?? shapeSignal?.operation ?? "other";

  // If we have a capability but no operation, infer a safe default.
  if (capability !== "other" && operation === "other") {
    operation = inferOperationForCapability(capability);
  }

  const result: Classification = { capability, operation, signals };
  if (
    (capability === "network" || capability === "message") &&
    operation === "read" &&
    argsLookExternal(args)
  ) {
    result.untrustedRead = true;
    signals.push("argument shape suggests external/untrusted content");
  }
  return result;
}

interface PartialClassification {
  capability?: Capability;
  operation?: Operation;
}

function classifyByName(
  name: string,
  signals: string[],
): PartialClassification | null {
  if (!name) return null;
  const part: PartialClassification = {};

  // Word-boundary helper: split tokens on `_`, `-`, and `/`.
  const tokens = name.split(/[_\-/]/).filter(Boolean);
  const hasToken = (re: RegExp): boolean => tokens.some((t) => re.test(t));

  // Capability hints from name tokens.
  if (hasToken(/^(file|dir|directory|path|folder|fs)s?$/)) {
    part.capability = "filesystem";
    signals.push(`name contains a filesystem hint`);
  } else if (hasToken(/^(shell|bash|exec|execute|command|cmd|process|spawn|run)$/)) {
    part.capability = "shell";
    signals.push(`name contains a shell/exec hint`);
  } else if (
    hasToken(/^(http|https|fetch|request|url|web|api|get|post|put|patch|delete)$/) ||
    /_(get|post|put|patch|delete)$/.test(name)
  ) {
    part.capability = "network";
    signals.push(`name contains a network hint`);
  } else if (hasToken(/^(email|mail|message|msg|slack|sms|telegram|discord)$/)) {
    part.capability = "message";
    signals.push(`name contains a messaging hint`);
  } else if (
    hasToken(/^(pay|charge|invoice|transfer|payment|checkout|stripe|refund)$/)
  ) {
    part.capability = "payment";
    signals.push(`name contains a payment hint`);
  } else if (hasToken(/^(secret|credential|vault|token|key)$/)) {
    part.capability = "secret";
    signals.push(`name contains a secret-store hint`);
  }

  // Operation hints.
  if (/^(read|get|list|fetch|search|describe|show|find|view|cat|head|tail)/.test(name)) {
    part.operation = "read";
  } else if (/^(delete|remove|rm|drop|destroy|purge)/.test(name) || /_delete$/.test(name)) {
    part.operation = "delete";
  } else if (
    /^(write|create|update|edit|set|put|patch|move|append|insert|save|upload)/.test(name)
  ) {
    part.operation = "write";
  } else if (/^(exec|execute|run|spawn|invoke|call)/.test(name) || /_exec$/.test(name)) {
    part.operation = "execute";
  } else if (
    /^(send|post|notify|publish|emit)/.test(name) ||
    /_send$/.test(name) ||
    /_post$/.test(name)
  ) {
    part.operation = "send";
  } else if (/^(pay|charge|transfer|spend)/.test(name)) {
    part.operation = "spend";
  }

  if (part.operation) signals.push(`name verb suggests operation=${part.operation}`);
  return part.capability || part.operation ? part : null;
}

function classifyByArgs(
  args: Record<string, unknown>,
  signals: string[],
): PartialClassification | null {
  if (!args || typeof args !== "object") return null;

  const part: PartialClassification = {};
  const keys = Object.keys(args).map((k) => k.toLowerCase());

  if (keys.some((k) => k === "amount" || k === "currency" || k === "price")) {
    part.capability = "payment";
    part.operation = "spend";
    signals.push("args contain amount/currency → payment");
    return part;
  }

  if (
    keys.some((k) =>
      ["to", "recipient", "recipients", "subject", "body", "channel"].includes(k),
    )
  ) {
    part.capability = "message";
    part.operation = "send";
    signals.push("args contain to/recipient/subject → message send");
    return part;
  }

  if (keys.some((k) => k === "url" || k === "uri" || k === "endpoint")) {
    part.capability = "network";
    signals.push("args contain url/uri → network");
  }

  if (
    keys.some((k) =>
      ["path", "filepath", "filename", "file", "dir", "directory"].includes(k),
    )
  ) {
    if (!part.capability) part.capability = "filesystem";
    signals.push("args contain path/file → filesystem");
  }

  if (keys.some((k) => ["command", "cmd", "argv", "script"].includes(k))) {
    part.capability = "shell";
    part.operation = "execute";
    signals.push("args contain command/cmd/script → shell execute");
  }

  return part.capability || part.operation ? part : null;
}

function inferOperationForCapability(c: Capability): Operation {
  switch (c) {
    case "filesystem":
      return "read"; // safest assumption when unknown
    case "shell":
      return "execute";
    case "network":
      return "read";
    case "message":
      return "send";
    case "payment":
      return "spend";
    case "secret":
      return "read";
    case "other":
      return "other";
  }
}

function argsLookExternal(args: Record<string, unknown>): boolean {
  if (!args) return false;
  for (const [k, v] of Object.entries(args)) {
    const kl = k.toLowerCase();
    if ((kl === "url" || kl === "uri" || kl === "endpoint") && typeof v === "string") {
      // External if the URL is not loopback / localhost / .local.
      if (/^https?:\/\//i.test(v) && !/^https?:\/\/(127\.|localhost|0\.0\.0\.0|::1|.+\.local)/i.test(v)) {
        return true;
      }
    }
  }
  return false;
}
