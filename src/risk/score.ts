/**
 * Combine a `Classification` and a trifecta snapshot into a risk label with
 * plain-English reasons. Pure function: same inputs → same outputs.
 *
 * Risk labels:
 *   - `critical`: would spend money, would exfiltrate via the lethal trifecta,
 *                 or attempts a secret read followed by outbound (the canonical
 *                 exfil shape).
 *   - `high`:     shell execute, filesystem delete, outbound send with prior
 *                 untrusted content in the session.
 *   - `medium`:   filesystem write, outbound send without prior untrusted reads,
 *                 untrusted-content reads while we already have private reads.
 *   - `low`:      plain reads (filesystem read of local files, network fetch on
 *                 its own without trifecta context).
 *
 * The label feeds into the policy engine's `risk_min` match. Reasons feed
 * the audit log and the approval prompt — the human deciding `approve/deny`
 * needs to see *why* this was flagged.
 */

import type { Classification } from "./classify.js";
import type { TrifectaSnapshot } from "./trifecta.js";

export type Risk = "low" | "medium" | "high" | "critical";

export interface RiskAssessment {
  risk: Risk;
  reasons: string[];
}

const RISK_ORDER: Risk[] = ["low", "medium", "high", "critical"];

export function maxRisk(a: Risk, b: Risk): Risk {
  return RISK_ORDER.indexOf(a) >= RISK_ORDER.indexOf(b) ? a : b;
}

export function scoreRisk(
  c: Classification,
  trifecta: TrifectaSnapshot,
): RiskAssessment {
  const reasons: string[] = [];
  let risk: Risk = "low";

  // Payments always escalate.
  if (c.capability === "payment") {
    risk = maxRisk(risk, "critical");
    reasons.push(
      "payment capability — money movement is always treated as critical",
    );
  }

  // Lethal trifecta wins.
  if (trifecta.isLethal) {
    risk = maxRisk(risk, "critical");
    reasons.push(
      "outbound action after reading private data AND ingesting untrusted external content — the lethal trifecta is the classic exfiltration shape",
    );
    for (const r of trifecta.reasons) reasons.push(`  - ${r}`);
  }

  // Secret reads followed by outbound have the same shape as exfil even
  // before all three legs land.
  if (c.capability === "secret" && c.operation === "read" && trifecta.outboundAttempted) {
    risk = maxRisk(risk, "critical");
    reasons.push("secret read after session already attempted outbound — exfil shape");
  }

  // Shell execution: nothing in the agent's plan should run unreviewed code.
  if (c.capability === "shell" && c.operation === "execute") {
    risk = maxRisk(risk, "high");
    reasons.push("shell execute — arbitrary code with the user's privileges");
  }

  // Filesystem delete is destructive.
  if (c.capability === "filesystem" && c.operation === "delete") {
    risk = maxRisk(risk, "high");
    reasons.push("filesystem delete — destructive and often irreversible");
  }

  // Outbound (network send / message send) without trifecta is still elevated
  // once we've ingested untrusted content.
  if (
    (c.capability === "network" || c.capability === "message") &&
    (c.operation === "send" || c.operation === "write")
  ) {
    if (trifecta.sawUntrusted) {
      risk = maxRisk(risk, "high");
      reasons.push(
        "outbound send while session has already ingested untrusted external content",
      );
    } else {
      risk = maxRisk(risk, "medium");
      reasons.push("outbound send — leaves the local machine");
    }
  }

  // Filesystem write is moderate (less than delete, more than read).
  if (c.capability === "filesystem" && c.operation === "write") {
    risk = maxRisk(risk, "medium");
    reasons.push("filesystem write — modifies local state");
  }

  // Untrusted reads after we already have private reads close the gap toward
  // a lethal session.
  if (
    c.operation === "read" &&
    c.untrustedRead &&
    trifecta.readPrivate
  ) {
    risk = maxRisk(risk, "medium");
    reasons.push(
      "ingesting external content into a session that already read private data",
    );
  }

  // Plain reads of local files: low risk by default.
  if (
    risk === "low" &&
    c.operation === "read"
  ) {
    reasons.push("plain read operation");
  }

  if (reasons.length === 0) {
    reasons.push(`uncategorized ${c.capability}/${c.operation} call`);
  }

  return { risk, reasons };
}
