import { defineConfig } from "tsup";

export default defineConfig([
  {
    entry: { cli: "src/cli.ts" },
    format: ["esm"],
    target: "node20",
    platform: "node",
    clean: true,
    sourcemap: true,
    dts: false,
    splitting: false,
    shims: false,
    banner: { js: "#!/usr/bin/env node" },
  },
  {
    entry: { index: "src/index.ts" },
    format: ["esm"],
    target: "node20",
    platform: "node",
    clean: false,
    sourcemap: true,
    dts: true,
    splitting: false,
    shims: false,
  },
  {
    entry: {
      "demo/mock-server": "demo/mock-server.ts",
      "demo/attack-scenario": "demo/attack-scenario.ts",
    },
    format: ["esm"],
    target: "node20",
    platform: "node",
    clean: false,
    sourcemap: true,
    dts: false,
    splitting: false,
    shims: false,
  },
]);
