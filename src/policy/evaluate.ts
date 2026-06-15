/**
 * Policy evaluator: turn a classified+scored call into a `Verdict`.
 *
 * Semantics: rules evaluate top-to-bottom, first match wins. Within a rule's
 * `match`, all listed fields are AND-ed; missing fields are "don't care".
 * If no rule matches, the policy's `defaults.on_unmatched` action applies.
 *
 * The evaluator is pure: same `(policy, input)` → same `Verdict`. Determinism
 * is a hard requirement; tests assert it.
 */

import type { Classification } from "../risk/classify.js";
import type { TrifectaSnapshot } from "../risk/trifecta.js";
import type { RiskAssessment } from "../risk/score.js";
import type { Policy, PolicyAction, PolicyRule } from "./schema.js";

const RISK_LEVELS = ["low", "medium", "high", "critical"] as const;

export interface EvaluateInput {
  toolName: string;
  classification: Classification;
  trifecta: TrifectaSnapshot;
  assessment: RiskAssessment;
}

export interface Verdict {
  action: PolicyAction;
  /** Name of the matching rule, or "defaults" when on_unmatched fired. */
  ruleName: string;
  /** Plain-English explanation surfaced in the approval prompt + audit log. */
  reason: string;
  /** Optional rule note carried through unchanged. */
  note?: string;
}

export function evaluate(policy: Policy, input: EvaluateInput): Verdict {
  for (const rule of policy.rules) {
    if (ruleMatches(rule, input)) {
      return {
        action: rule.action,
        ruleName: rule.name,
        reason: explainMatch(rule, input),
        ...(rule.note ? { note: rule.note } : {}),
      };
    }
  }
  return {
    action: policy.defaults.on_unmatched,
    ruleName: "defaults.on_unmatched",
    reason: `no rule matched; applying default action '${policy.defaults.on_unmatched}'`,
  };
}

function ruleMatches(rule: PolicyRule, input: EvaluateInput): boolean {
  const m = rule.match;
  if (m.capability !== undefined && m.capability !== input.classification.capability) return false;
  if (m.operation !== undefined && m.operation !== input.classification.operation) return false;
  if (m.risk_min !== undefined && !riskAtLeast(input.assessment.risk, m.risk_min)) return false;
  if (m.trifecta === true && !input.trifecta.isLethal) return false;
  if (m.tool !== undefined && !toolMatches(m.tool, input.toolName)) return false;
  return true;
}

function riskAtLeast(actual: string, min: string): boolean {
  const a = RISK_LEVELS.indexOf(actual as (typeof RISK_LEVELS)[number]);
  const b = RISK_LEVELS.indexOf(min as (typeof RISK_LEVELS)[number]);
  if (a === -1 || b === -1) return false;
  return a >= b;
}

/**
 * Tiny tool-name matcher. Supports an exact-string match and a single
 * trailing `*` glob (`stripe_*` matches `stripe_create_charge`). No full
 * regex on purpose — the DSL stays tiny.
 */
function toolMatches(pattern: string, toolName: string): boolean {
  if (pattern === toolName) return true;
  if (pattern.endsWith("*")) {
    const prefix = pattern.slice(0, -1);
    return toolName.startsWith(prefix);
  }
  return false;
}

function explainMatch(rule: PolicyRule, input: EvaluateInput): string {
  const parts: string[] = [];
  const m = rule.match;
  if (m.capability) parts.push(`capability=${input.classification.capability}`);
  if (m.operation) parts.push(`operation=${input.classification.operation}`);
  if (m.risk_min) parts.push(`risk=${input.assessment.risk} >= ${m.risk_min}`);
  if (m.trifecta === true) parts.push(`trifecta=true`);
  if (m.tool) parts.push(`tool='${input.toolName}' matches '${m.tool}'`);
  const conditions = parts.length ? ` (${parts.join(", ")})` : "";
  return `rule '${rule.name}' matched${conditions}`;
}
