import { Command } from "commander";
import { writeFileSync, readdirSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

import { PRODUCT_NAME, getPackageVersion } from "./constants.js";
import { startStdioProxy } from "./proxy/stdioProxy.js";
import { AuditLog, verifyChain } from "./audit/log.js";
import { createAuditingInterceptor } from "./audit/interceptor.js";
import { generateKeypair } from "./audit/sign.js";
import { airlockPaths, ensureAirlockHome } from "./config.js";
import { loadPolicy, InvalidPolicyError } from "./policy/load.js";
import { evaluate } from "./policy/evaluate.js";
import { classify } from "./risk/classify.js";
import { TrifectaTracker } from "./risk/trifecta.js";
import { scoreRisk } from "./risk/score.js";
import { ApprovalQueue } from "./approval/queue.js";
import { createCliApprovalChannel } from "./approval/cli.js";
import { createNotifyApprovalChannel } from "./approval/notify.js";
import { watchPendingResolutions } from "./approval/watcher.js";

/**
 * Build the root commander program. Exposed as a function so tests can
 * exercise commands without invoking process.exit on the test runner.
 */
export function buildProgram(): Command {
  const program = new Command();
  program
    .name(PRODUCT_NAME)
    .description(
      "A firewall and flight recorder for AI agents — least-privilege approval and a tamper-evident audit log for every action your agent takes.",
    )
    .version(getPackageVersion(), "-v, --version", "Print the installed version");

  // `airlock wrap -- <command...>` spawns the downstream MCP server and relays
  // newline-delimited JSON-RPC between the upstream client (on this process's
  // stdio) and that server. The interceptor records every tools/call to the
  // tamper-evident audit log and consults the active policy. `ask` verdicts
  // pause the call asynchronously (other traffic keeps flowing) while a
  // human approves via CLI prompt, desktop notification, or
  // `airlock approve <id>` from another terminal.
  program
    .command("wrap")
    .description(
      "Wrap a downstream MCP server: airlock wrap [--policy <file>] [--approval-timeout-ms <ms>] -- <command> [args...]",
    )
    .option("--policy <file>", "Path to an explicit airlock policy YAML file")
    .option(
      "--approval-timeout-ms <ms>",
      "Milliseconds to wait for human approval on 'ask' verdicts before defaulting to deny",
      "60000",
    )
    .option(
      "--no-cli-approval",
      "Disable the interactive TTY approval prompt (use airlock approve/deny instead)",
    )
    .option(
      "--no-notify",
      "Disable desktop notifications for approval requests",
    )
    .argument("<command...>", "Downstream MCP server command and arguments")
    .allowUnknownOption(true)
    .action(
      async (
        commandTokens: string[],
        opts: {
          policy?: string;
          approvalTimeoutMs?: string;
          cliApproval?: boolean;
          notify?: boolean;
        },
      ) => {
        if (!commandTokens || commandTokens.length === 0) {
          process.stderr.write(
            `${PRODUCT_NAME} wrap: missing command. Use: airlock wrap -- <command> [args...]\n`,
          );
          process.exit(2);
        }
        let loaded;
        try {
          loaded = loadPolicy({ explicit: opts.policy });
        } catch (err) {
          if (err instanceof InvalidPolicyError) {
            process.stderr.write(`${PRODUCT_NAME}: ${err.message}\n`);
          } else {
            process.stderr.write(
              `${PRODUCT_NAME}: failed to load policy: ${(err as Error).message}\n`,
            );
          }
          process.exit(3);
        }
        const paths = ensureAirlockHome();
        const timeoutMs = Math.max(
          1_000,
          parseInt(opts.approvalTimeoutMs ?? "60000", 10) || 60_000,
        );
        const channels: Array<
          (req: import("./approval/queue.js").ApprovalRequestSummary, queue: ApprovalQueue) => void
        > = [];
        if (opts.cliApproval !== false) channels.push(createCliApprovalChannel());
        if (opts.notify !== false) channels.push(createNotifyApprovalChannel());
        const approvals = new ApprovalQueue({
          timeoutMs,
          pendingDir: paths.pendingDir,
          onEnqueue: (req, queue) => {
            for (const ch of channels) {
              try {
                ch(req, queue);
              } catch {
                // channel failure must not break the approval flow
              }
            }
          },
        });
        const watcher = watchPendingResolutions(paths.pendingDir, approvals);

        const [command, ...args] = commandTokens;
        const auditLog = new AuditLog();
        const handle = startStdioProxy({
          command: command!,
          args,
          interceptor: createAuditingInterceptor({
            log: auditLog,
            policy: loaded.policy,
            approvals,
          }),
          onReady: ({ sessionId, childPid }) => {
            process.stderr.write(
              `${PRODUCT_NAME}: wrapping pid=${childPid ?? "?"} session=${sessionId} policy=${loaded.source}${loaded.path ? `:${loaded.path}` : ""}\n`,
            );
          },
        });

        const onSignal = (signal: NodeJS.Signals) => {
          handle.shutdown(signal).catch(() => undefined);
        };
        process.on("SIGINT", onSignal);
        process.on("SIGTERM", onSignal);

        const code = await handle.exited;
        watcher.stop();
        approvals.shutdown();
        process.exit(code ?? 0);
      },
    );

  program
    .command("init")
    .description("Initialize Airlock state directory and generate signing keypair")
    .option("--force", "Regenerate signing keypair even if one exists", false)
    .action((opts: { force?: boolean }) => {
      const paths = ensureAirlockHome();
      const { privateKeyPath, publicKeyPath } = generateKeypair(paths, !!opts.force);
      process.stdout.write(
        `${PRODUCT_NAME}: initialized\n  home=${paths.homeDir}\n  privateKey=${privateKeyPath}\n  publicKey=${publicKeyPath}\n`,
      );
    });

  program
    .command("log")
    .description("Print the audit log (most recent first)")
    .option("--json", "Emit raw JSONL instead of a human view", false)
    .option("-n, --tail <n>", "Show only the last N entries", "50")
    .action((opts: { json?: boolean; tail?: string }) => {
      const log = new AuditLog();
      const entries = log.readAll();
      const tailN = Math.max(1, parseInt(opts.tail ?? "50", 10) || 50);
      const recent = entries.slice(-tailN).reverse();
      if (opts.json) {
        for (const e of recent) process.stdout.write(JSON.stringify(e) + "\n");
        return;
      }
      if (recent.length === 0) {
        process.stdout.write(`${PRODUCT_NAME}: audit log is empty\n`);
        return;
      }
      for (const e of recent) {
        const risk = e.risk ? ` risk=${e.risk}` : "";
        const cap = e.capability ? ` ${e.capability}` : "";
        const op = e.operation ? `/${e.operation}` : "";
        const rule = e.ruleName ? ` rule=${e.ruleName}` : "";
        const waited = e.waitedMs ? ` waited=${e.waitedMs}ms` : "";
        const resolver = e.resolvedBy ? ` by=${e.resolvedBy}` : "";
        process.stdout.write(
          `[${e.ts}] seq=${e.seq} ${e.verdict.toUpperCase().padEnd(5)} ${e.tool}${cap}${op}${risk}${rule}${waited}${resolver} ${e.latencyMs}ms — ${e.reason}\n`,
        );
      }
    });

  program
    .command("verify")
    .description("Verify the audit log hash chain is intact")
    .action(() => {
      const paths = airlockPaths();
      const result = verifyChain(paths.auditLog);
      if (result.ok) {
        process.stdout.write(
          `${PRODUCT_NAME}: audit chain OK (${result.total} entries)\n`,
        );
        return;
      }
      process.stderr.write(
        `${PRODUCT_NAME}: audit chain BROKEN at seq=${result.firstBrokenSeq} — ${result.reason}\n`,
      );
      process.exit(1);
    });

  program
    .command("approve <id>")
    .description("Approve a pending Airlock approval out-of-band")
    .action((id: string) => {
      writePendingResolution(id, "approve");
    });

  program
    .command("deny <id>")
    .description("Deny a pending Airlock approval out-of-band")
    .action((id: string) => {
      writePendingResolution(id, "deny");
    });

  program
    .command("pending")
    .description("List approvals currently waiting (from ~/.airlock/pending/)")
    .action(() => {
      const paths = airlockPaths();
      let names: string[] = [];
      try {
        names = readdirSync(paths.pendingDir).filter((n) => n.endsWith(".json"));
      } catch {
        names = [];
      }
      if (names.length === 0) {
        process.stdout.write(`${PRODUCT_NAME}: no pending approvals\n`);
        return;
      }
      for (const n of names) {
        try {
          const body = JSON.parse(readFileSync(join(paths.pendingDir, n), "utf8"));
          process.stdout.write(
            `${body.id}  ${body.ts}  ${body.tool} (${body.capability ?? "?"}/${body.operation ?? "?"}, ${body.risk ?? "?"})${body.trifecta ? " TRIFECTA" : ""}\n  ${body.reason}\n`,
          );
        } catch {
          process.stdout.write(`${n}  (malformed pending file)\n`);
        }
      }
    });

  const policyCmd = program
    .command("policy")
    .description("Inspect the active policy");

  policyCmd
    .command("check")
    .description(
      "Show which rule would fire for a sample call. Useful for tuning policies.",
    )
    .requiredOption("--tool <name>", "Tool name (e.g. http_post)")
    .option(
      "--args <json>",
      "Tool arguments as a JSON string (default: {})",
      "{}",
    )
    .option("--policy <file>", "Path to an explicit airlock policy YAML file")
    .option(
      "--trifecta",
      "Treat the session as having completed the lethal trifecta",
      false,
    )
    .action((opts: { tool: string; args: string; policy?: string; trifecta?: boolean }) => {
      let parsedArgs: unknown;
      try {
        parsedArgs = JSON.parse(opts.args);
      } catch (err) {
        process.stderr.write(
          `${PRODUCT_NAME} policy check: --args must be valid JSON: ${(err as Error).message}\n`,
        );
        process.exit(2);
      }
      let loaded;
      try {
        loaded = loadPolicy({ explicit: opts.policy });
      } catch (err) {
        process.stderr.write(`${PRODUCT_NAME}: ${(err as Error).message}\n`);
        process.exit(3);
      }
      const classification = classify({ name: opts.tool, arguments: parsedArgs });
      const tracker = new TrifectaTracker();
      if (opts.trifecta) {
        tracker.observe("check", classify({ name: "read_file", arguments: { path: "/x" } }));
        tracker.observe("check", classify({ name: "fetch", arguments: { url: "https://example.com" } }));
      }
      const snapshot = tracker.inspect("check", classification);
      const assessment = scoreRisk(classification, snapshot);
      const verdict = evaluate(loaded.policy, {
        toolName: opts.tool,
        classification,
        trifecta: snapshot,
        assessment,
      });
      process.stdout.write(
        `${PRODUCT_NAME} policy check\n` +
          `  policy source: ${loaded.source}${loaded.path ? ` (${loaded.path})` : ""}\n` +
          `  tool:          ${opts.tool}\n` +
          `  classification: capability=${classification.capability} operation=${classification.operation}${classification.untrustedRead ? " untrustedRead=true" : ""}\n` +
          `  trifecta:      ${snapshot.isLethal}\n` +
          `  risk:          ${assessment.risk}\n` +
          `  risk reasons:  ${assessment.reasons.join(" | ")}\n` +
          `  verdict:       ${verdict.action} (rule '${verdict.ruleName}')\n` +
          `  reason:        ${verdict.reason}\n`,
      );
    });

  return program;
}

function writePendingResolution(id: string, resolution: "approve" | "deny"): void {
  const paths = ensureAirlockHome();
  const pendingPath = join(paths.pendingDir, `${id}.json`);
  if (!existsSync(pendingPath)) {
    process.stderr.write(
      `${PRODUCT_NAME}: no pending approval with id '${id}' in ${paths.pendingDir}\n  Run 'airlock pending' to list current ids.\n`,
    );
    process.exit(2);
  }
  const resolutionPath = join(paths.pendingDir, `${id}.resolution`);
  writeFileSync(resolutionPath, resolution + "\n", { mode: 0o600 });
  process.stdout.write(`${PRODUCT_NAME}: wrote ${resolution} for ${id}\n`);
}

// When invoked directly via the bin shim, parse argv. When imported (tests, library),
// nothing happens automatically. `process.argv[1]` is the script path that node was
// asked to run; if it matches our module URL we are the entry point.
const isDirectInvocation = (() => {
  try {
    const invokedPath = process.argv[1];
    if (!invokedPath) return false;
    const here = new URL(import.meta.url).pathname;
    return invokedPath === here || here.endsWith(invokedPath);
  } catch {
    return false;
  }
})();

if (isDirectInvocation) {
  buildProgram().parseAsync(process.argv).catch((err: unknown) => {
    process.stderr.write(`${PRODUCT_NAME}: fatal: ${(err as Error)?.message ?? String(err)}\n`);
    process.exit(1);
  });
}
