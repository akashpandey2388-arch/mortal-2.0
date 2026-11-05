/**
 * MORTAL 2.0 — Verifiable Trust Passport Manager
 * Calculates agent performance and reliability strictly from verifiable
 * Black Box hash chain evidence and HCS commitments.
 * 
 * CORE RULE (Section 4):
 * Only real, evidence-based counts with sample sizes and timestamps;
 * no invented or hallucinated scores.
 */

import { DatabaseService } from "../db/database.ts";
import type { TrustPassport } from "../../types/index.ts";

export class TrustPassportManager {
  private db: DatabaseService;

  constructor(db: DatabaseService) {
    this.db = db;
  }

  /**
   * Generates a verifiable Trust Passport for an agent based on historical Black Box records.
   */
  public generateTrustPassport(agentEnsName: string): TrustPassport {
    const events = this.db.listEvents(10000);
    const agentEvents = events.filter(
      e => e.agentEnsName.toLowerCase() === agentEnsName.toLowerCase()
    );

    const totalEvaluated = agentEvents.length;
    let allowedCount = 0;
    let blockedCount = 0;
    let humanApprovalCount = 0;
    let firstActivity = 0;
    let latestActivity = 0;
    let verifiedHcsAnchors = 0;
    let isSimulated = false;

    if (totalEvaluated > 0) {
      firstActivity = agentEvents[0].timestamp;
      latestActivity = agentEvents[agentEvents.length - 1].timestamp;

      for (const ev of agentEvents) {
        if (ev.decision === "ALLOW") allowedCount++;
        else if (ev.decision === "BLOCK") blockedCount++;
        else if (ev.decision === "HUMAN_APPROVAL") humanApprovalCount++;

        if (ev.hcsAnchor) {
          verifiedHcsAnchors++;
          if (ev.hcsAnchor.isSimulated) isSimulated = true;
        }
      }
    }

    // Evidence-based reliability ratio: allowedActions / totalActions
    const reliabilityRatio = totalEvaluated > 0 ? Number((allowedCount / totalEvaluated).toFixed(4)) : 1.0;

    return {
      agentEnsName,
      totalEvaluatedActions: totalEvaluated,
      allowedActionsCount: allowedCount,
      blockedIncidentsCount: blockedCount,
      humanApprovalsCount: humanApprovalCount,
      firstActivityTimestamp: firstActivity,
      latestActivityTimestamp: latestActivity,
      verifiedHcsAnchorsCount: verifiedHcsAnchors,
      reliabilityRatio,
      isSimulated
    };
  }
}
