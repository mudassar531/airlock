/**
 * Zod schema for the Airlock policy DSL.
 *
 * The DSL is intentionally tiny — a solo dev should be able to read the
 * default policy in 30 seconds. Resist adding knobs.
 *
 * Schema (YAML / JSON):
 *
 *   version: 1
 *   defaults:
 *     on_unmatched: ask          # allow | deny | ask | log
 *   rules:
 *     - name: never-spend-money
 *       match:
 *         capability: payment    # any of the 7 capabilities
 *         operation: spend       # any of the 7 operations
 *         risk_min: high         # low | medium | high | critical
 *         trifecta: true         # boolean, only matches when true
 *         tool: stripe_create_*  # glob (literal or trailing-*); optional
 *       action: deny             # allow | deny | ask | log
 *
 * Rule semantics:
 *   - rules evaluate top-to-bottom, first match wins.
 *   - within a rule's `match`, all listed fields must match (logical AND).
 *   - any missing match field is "don't care".
 *   - `risk_min` matches when the call's risk is at least the given level.
 *   - `trifecta: true` matches only when the trifecta is lethal on this call.
 *   - if no rule matches, `defaults.on_unmatched` applies.
 *
 * Validation is strict — unknown fields throw. The loader is fail-closed:
 * an invalid policy refuses to run rather than silently allowing.
 */

import { z } from "zod";

export const ActionSchema = z.enum(["allow", "deny", "ask", "log"]);
export type PolicyAction = z.infer<typeof ActionSchema>;

export const CapabilitySchema = z.enum([
  "filesystem",
  "shell",
  "network",
  "message",
  "payment",
  "secret",
  "other",
]);

export const OperationSchema = z.enum([
  "read",
  "write",
  "delete",
  "execute",
  "send",
  "spend",
  "other",
]);

export const RiskSchema = z.enum(["low", "medium", "high", "critical"]);

export const RuleMatchSchema = z
  .object({
    capability: CapabilitySchema.optional(),
    operation: OperationSchema.optional(),
    risk_min: RiskSchema.optional(),
    trifecta: z.literal(true).optional(),
    tool: z.string().min(1).optional(),
  })
  .strict()
  .refine(
    (m) =>
      m.capability !== undefined ||
      m.operation !== undefined ||
      m.risk_min !== undefined ||
      m.trifecta !== undefined ||
      m.tool !== undefined,
    { message: "rule match must specify at least one of: capability, operation, risk_min, trifecta, tool" },
  );

export const RuleSchema = z
  .object({
    name: z.string().min(1),
    match: RuleMatchSchema,
    action: ActionSchema,
    /** Optional explanation surfaced in the approval prompt + audit log. */
    note: z.string().optional(),
  })
  .strict();

export const PolicySchema = z
  .object({
    version: z.literal(1),
    defaults: z
      .object({
        on_unmatched: ActionSchema,
      })
      .strict(),
    rules: z.array(RuleSchema).default([]),
  })
  .strict();

export type Policy = z.infer<typeof PolicySchema>;
export type PolicyRule = z.infer<typeof RuleSchema>;
export type PolicyRuleMatch = z.infer<typeof RuleMatchSchema>;
