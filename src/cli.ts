import { Command } from "commander";
import { PRODUCT_NAME, getPackageVersion } from "./constants.js";
import { startStdioProxy } from "./proxy/stdioProxy.js";
import { AuditLog, verifyChain } from "./audit/log.js";
import { createAuditingInterceptor } from "./audit/interceptor.js";
import { generateKeypair } from "./audit/sign.js";
import { airlockPaths, ensureAirlockHome } from "./config.js";

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
  // tamper-evident audit log at ~/.airlock/audit.log.
  program
    .command("wrap")
    .description(
      "Wrap a downstream MCP server: airlock wrap -- <command> [args...]",
    )
    .argument("<command...>", "Downstream MCP server command and arguments")
    .allowUnknownOption(true)
    .action(async (commandTokens: string[]) => {
      if (!commandTokens || commandTokens.length === 0) {
        process.stderr.write(
          `${PRODUCT_NAME} wrap: missing command. Use: airlock wrap -- <command> [args...]\n`,
        );
        process.exit(2);
      }
      const [command, ...args] = commandTokens;
      const auditLog = new AuditLog();
      const handle = startStdioProxy({
        command: command!,
        args,
        interceptor: createAuditingInterceptor({ log: auditLog }),
        onReady: ({ sessionId, childPid }) => {
          process.stderr.write(
            `${PRODUCT_NAME}: wrapping pid=${childPid ?? "?"} session=${sessionId}\n`,
          );
        },
      });

      const onSignal = (signal: NodeJS.Signals) => {
        handle.shutdown(signal).catch(() => undefined);
      };
      process.on("SIGINT", onSignal);
      process.on("SIGTERM", onSignal);

      const code = await handle.exited;
      process.exit(code ?? 0);
    });

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
        process.stdout.write(
          `[${e.ts}] seq=${e.seq} ${e.verdict.toUpperCase().padEnd(5)} ${e.tool}${cap}${op}${risk} ${e.latencyMs}ms — ${e.reason}\n`,
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

  return program;
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
