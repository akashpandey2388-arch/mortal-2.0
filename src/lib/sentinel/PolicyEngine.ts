/**
 * MORTAL 2.0 — Sentinel Policy Engine
 * Evaluates payment parameters, destination allowlists, transaction caps,
 * rolling frequency/spending limits, and approval thresholds.
 */

import type { ActionProposal, ReasonCode } from "../../types/index.ts";
import { DEFAULT_POLICY, type PolicyConfig } from "../../../config/policy.ts";
import { DatabaseService } from "../db/database.ts";
import { CURRENCY_CONFIG, demoUnitsToTinybars } from "../../../config/currency.ts";

export interface PolicyCheckResult {
  passed: boolean;
  requiresHumanApproval: boolean;
  reasonCodes: ReasonCode[];
  errors: string[];
}

export class PolicyEngine {
  private policy: PolicyConfig;
  private db: DatabaseService;

  constructor(db: DatabaseService, policy: PolicyConfig = DEFAULT_POLICY) {
    this.db = db;
    this.policy = policy;
  }

  /**
   * Validates payment action against allowlists and spending bounds.
   */
  public evaluatePaymentPolicy(proposal: ActionProposal): PolicyCheckResult {
    const reasons: ReasonCode[] = [];
    const errors: string[] = [];
    let requiresApproval = false;

    const params = proposal.parameters || {};
    const destination = params.destinationAccountId || "";
    const demoAmount = params.demoAmount !== undefined ? params.demoAmount : 0;

    // 1. Destination in merchant allowlist check
    const isApprovedDestination = this.policy.approvedMerchants.some(
      m => m.hederaAccountId === destination || m.endpoint === destination
    );

    if (!isApprovedDestination) {
      reasons.push("DEST_NOT_ALLOWLISTED");
      errors.push(`Destination "${destination}" is not in approved merchant allowlist`);
    }

    // 2. Amount <= max per payment check (₹5,000 limit)
    if (demoAmount > this.policy.paymentLimits.maxPerPaymentDemo) {
      reasons.push("OVER_LIMIT");
      errors.push(
        `Requested amount ₹${demoAmount.toLocaleString()} exceeds maximum allowed per payment ceiling of ₹${this.policy.paymentLimits.maxPerPaymentDemo.toLocaleString()}`
      );
    }

    // 3. Period spending limit & frequency checks
    const recentEvents = this.db.listEvents(100);
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - this.policy.paymentLimits.periodDurationSeconds;
    const hourStart = now - 3600;

    let periodSpend = demoAmount;
    let hourlyCount = 1;

    for (const ev of recentEvents) {
      if (ev.decision === "ALLOW" && ev.proposedAction.tool === "execute_vendor_payment") {
        const evAmount = ev.paymentReference?.demoAmount || ev.proposedAction.parameters?.demoAmount || 0;
        if (ev.timestamp >= windowStart) {
          periodSpend += evAmount;
        }
        if (ev.timestamp >= hourStart) {
          hourlyCount += 1;
        }
      }
    }

    if (periodSpend > this.policy.paymentLimits.periodSpendingLimitDemo) {
      reasons.push("PERIOD_SPENDING_LIMIT_EXCEEDED");
      errors.push(
        `Cumulative 24-hour spend ₹${periodSpend.toLocaleString()} exceeds period limit of ₹${this.policy.paymentLimits.periodSpendingLimitDemo.toLocaleString()}`
      );
    }

    if (hourlyCount > this.policy.paymentLimits.maxFrequencyPerHour) {
      reasons.push("FREQUENCY_LIMIT_EXCEEDED");
      errors.push(`Payment frequency ${hourlyCount}/hr exceeds allowed rate limit of ${this.policy.paymentLimits.maxFrequencyPerHour}/hr`);
    }

    // If any hard limit failed, return immediately with BLOCK codes
    if (reasons.length > 0) {
      return {
        passed: false,
        requiresHumanApproval: false,
        reasonCodes: reasons,
        errors
      };
    }

    // 4. Configurable human approval threshold (e.g. ₹2,000)
    if (demoAmount > this.policy.paymentLimits.humanApprovalThresholdDemo) {
      requiresApproval = true;
      reasons.push("APPROVAL_REQUIRED_AMOUNT_THRESHOLD");
      errors.push(
        `Amount ₹${demoAmount.toLocaleString()} exceeds autonomous threshold of ₹${this.policy.paymentLimits.humanApprovalThresholdDemo.toLocaleString()}; requires human approval`
      );
    }

    return {
      passed: true,
      requiresHumanApproval: requiresApproval,
      reasonCodes: reasons,
      errors
    };
  }
}
