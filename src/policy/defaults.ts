/**
 * Built-in default policy pack. Ships in the binary so a fresh install is
 * safe out of the box; mirrored to `policy.example.yaml` for users who want
 * to customize.
 *
 * The defaults implement the lethal-trifecta-first stance from the spec:
 *   - Never spend money without explicit human action.
 *   - Hold any action that completes the lethal trifecta for human approval.
 *   - Confirm destructive filesystem operations.
 *   - Confirm shell execution.
 *   - Confirm outbound messaging.
 *   - Allow plain reads to keep latency near zero on the safe path.
 *   - Anything else falls through to `on_unmatched: ask` — fail closed.
 */

import type { Policy } from "./schema.js";

export const DEFAULT_POLICY: Policy = {
  version: 1,
  defaults: {
    on_unmatched: "ask",
  },
  rules: [
    {
      name: "never-spend-money",
      match: { capability: "payment" },
      action: "deny",
      note: "Money movement requires explicit user action outside Airlock.",
    },
    {
      name: "hold-the-lethal-trifecta",
      match: { trifecta: true },
      action: "ask",
      note: "This call would complete the lethal trifecta (private read + untrusted content + outbound).",
    },
    {
      name: "confirm-destructive-fs",
      match: { capability: "filesystem", operation: "delete" },
      action: "ask",
      note: "Filesystem deletes are often irreversible.",
    },
    {
      name: "confirm-shell-exec",
      match: { capability: "shell" },
      action: "ask",
      note: "Shell execution can run arbitrary code with your privileges.",
    },
    {
      name: "confirm-outbound-send",
      match: { capability: "message", operation: "send" },
      action: "ask",
      note: "Outbound messages leave the local machine.",
    },
    {
      name: "allow-plain-reads",
      match: { operation: "read" },
      action: "allow",
      note: "Reads of local data are low-risk and frequent — keep them fast.",
    },
  ],
};

/**
 * The same content as `DEFAULT_POLICY`, serialized as YAML for
 * `policy.example.yaml` and the `airlock policy export` command. Kept inline
 * (not loaded from disk) so the binary is self-contained.
 */
export const DEFAULT_POLICY_YAML = `version: 1
defaults:
  on_unmatched: ask        # allow | deny | ask | log  — fail safe, not open
rules:
  - name: never-spend-money
    match: { capability: payment }
    action: deny
  - name: hold-the-lethal-trifecta
    match: { trifecta: true }
    action: ask
  - name: confirm-destructive-fs
    match: { capability: filesystem, operation: delete }
    action: ask
  - name: confirm-shell-exec
    match: { capability: shell }
    action: ask
  - name: confirm-outbound-send
    match: { capability: message, operation: send }
    action: ask
  - name: allow-plain-reads
    match: { operation: read }
    action: allow
`;
