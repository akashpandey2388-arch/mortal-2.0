/**
 * MORTAL 2.0 — Sentinel Risk Engine
 * Deterministic rule-based anomaly detection with asymmetric risk escalation.
 * 
 * CORE INVARIANT:
 * Risk engine signals and optional LLM evaluations can ONLY ADD caution (e.g. elevating ALLOW to HUMAN_APPROVAL).
 * Under NO circumstances can any heuristic, LLM output, or front-end input downgrade or bypass a deterministic BLOCK.
 */

import type { ActionProposal, DecisionType, ReasonCode } from "../../types/index.ts";

export interface RiskEvaluationResult {
  riskScore: number; // 0 (lowest) to 100 (highest)
  anomaliesDetected: string[];
  recommendedElevation?: "HUMAN_APPROVAL";
  reasonCode?: ReasonCode;
}

export class RiskEngine {
  /**
   * Evaluates action proposal for behavioral and semantic anomalies.
   */
  public evaluateRisk(proposal: ActionProposal): RiskEvaluationResult {
    let riskScore = 0;
    const anomalies: string[] = [];

    const params = proposal.parameters || {};

    // 1. Check for prompt injection / shell injection markers in parameters
    const serializedParams = JSON.stringify(params).toLowerCase();
    const suspiciousKeywords = [
      "ignore previous instructions",
      "drain wallet",
      "bypass sentinel",
      "sudo",
      "transfer all",
      "private key",
      "malicious"
    ];

    for (const kw of suspiciousKeywords) {
      if (serializedParams.includes(kw)) {
        riskScore += 70;
        anomalies.push(`Suspicious adversarial token pattern detected: "${kw}"`);
      }
    }

    // 2. Check for unusual off-pattern amounts (e.g. rapid succession or odd decimals)
    if (params.demoAmount && params.demoAmount > 1500) {
      riskScore += 25;
      anomalies.push("High-value expenditure approaching approval ceiling");
    }

    // 3. Check for external/unknown domain references
    if (params.filePath && (params.filePath.includes("..") || params.filePath.startsWith("/etc") || params.filePath.includes("system32"))) {
      riskScore += 80;
      anomalies.push("Path traversal pattern detected in file target");
    }

    // Asymmetric risk rule: If risk score exceeds warning threshold (> 40), recommend HUMAN_APPROVAL
    if (riskScore >= 40) {
      return {
        riskScore,
        anomaliesDetected: anomalies,
        recommendedElevation: "HUMAN_APPROVAL",
        reasonCode: "RISK_ANOMALY_DETECTED"
      };
    }

    return {
      riskScore,
      anomaliesDetected: anomalies
    };
  }
}
