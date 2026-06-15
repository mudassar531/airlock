import { Command } from "commander";
import { PRODUCT_NAME, getPackageVersion } from "./constants.js";

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

  // Subcommands are wired in later phases. Phase 0 ships only metadata.
  program
    .command("wrap")
    .description("Wrap a downstream MCP server (added in phase 1)")
    .helpOption(false)
    .action(() => {
      process.stderr.write(
        `${PRODUCT_NAME} wrap: not yet implemented in this phase. Coming in phase 1.\n`,
      );
      process.exit(2);
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
