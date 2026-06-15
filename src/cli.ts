import { Command } from "commander";
import { PRODUCT_NAME, getPackageVersion } from "./constants.js";
import { startStdioProxy } from "./proxy/stdioProxy.js";

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
  // stdio) and that server. The interceptor is identity in Phase 1; later
  // phases extend it to classify, audit, score, approve, and enforce policy.
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
      const handle = startStdioProxy({
        command: command!,
        args,
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
