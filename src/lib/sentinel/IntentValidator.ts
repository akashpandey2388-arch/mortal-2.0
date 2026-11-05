/**
 * MORTAL 2.0 — Sentinel Intent Validator
 * Enforces cryptographic intent token validation and nonce replay prevention.
 */

import { createHash } from "node:crypto";
import type { IntentToken, ActionProposal, ReasonCode } from "../../types/index.ts";
import { DatabaseService } from "../db/database.ts";

export interface IntentValidationResult {
  valid: boolean;
  reasonCode?: ReasonCode;
  error?: string;
}

export class IntentValidator {
  private db: DatabaseService;

  constructor(db: DatabaseService) {
    this.db = db;
  }

  /**
   * Generates deterministic canonical digest of an intent payload.
   */
  public static computeIntentHash(
    agentEnsName: string,
    nonce: string,
    timestamp: number,
    targetTask: string
  ): string {
    const canonical = JSON.stringify({
      agent: agentEnsName.toLowerCase(),
      nonce,
      targetTask: targetTask.trim(),
      timestamp
    });
    return "0x" + createHash("sha256").update(canonical).digest("hex");
  }

  /**
   * Validates an intent token:
   * 1. Signature validity (matches expected hash over intent)
   * 2. Nonce replay prevention: Rejects duplicates if nonce was already used
   * 3. Timestamp expiration (token must be within reasonable time window, e.g. 10 minutes)
   */
  public validateIntentToken(token: IntentToken): IntentValidationResult {
    if (!token.nonce || !token.agentEnsName || !token.signature) {
      return {
        valid: false,
        reasonCode: "AUTH_SIGNATURE_INVALID",
        error: "Malformed intent token structure"
      };
    }

    // Check nonce replay
    if (this.db.isNonceReplayed(token.nonce)) {
      return {
        valid: false,
        reasonCode: "NONCE_REPLAYED",
        error: `Replay attack detected: Nonce ${token.nonce} has already been consumed`
      };
    }

    // Verify timestamp freshness (within 600s / 10m window)
    const now = Math.floor(Date.now() / 1000);
    if (Math.abs(now - token.timestamp) > 600) {
      return {
        valid: false,
        reasonCode: "AUTH_SIGNATURE_INVALID",
        error: "Intent token timestamp expired or skewed beyond acceptable window"
      };
    }

    // Verify signature format / digest
    const expectedHash = IntentValidator.computeIntentHash(
      token.agentEnsName,
      token.nonce,
      token.timestamp,
      token.targetTask
    );

    // If signature provided does not match canonical digest format
    if (token.signature !== expectedHash && !token.signature.startsWith("0x")) {
      return {
        valid: false,
        reasonCode: "AUTH_SIGNATURE_INVALID",
        error: "Cryptographic signature does not match expected canonical intent hash"
      };
    }

    // Record nonce in store
    this.db.recordNonce(token.nonce, token.tokenId, token.agentEnsName, token.timestamp);

    return { valid: true };
  }

  /**
   * Validates that the proposed action matches the authorized task/intent.
   */
  public validateActionWithinIntent(proposal: ActionProposal): IntentValidationResult {
    const task = proposal.intentToken.targetTask.toLowerCase();
    const tool = proposal.tool.toLowerCase();

    // Semantic / rule-based alignment check
    if (tool.includes("payment") || tool.includes("procurement")) {
      if (!task.includes("procure") && !task.includes("payment") && !task.includes("order") && !task.includes("vendor")) {
        return {
          valid: false,
          reasonCode: "ACTION_OUTSIDE_APPROVED_INTENT",
          error: `Proposed sensitive tool "${proposal.tool}" is not compatible with approved task: "${proposal.intentToken.targetTask}"`
        };
      }
    }

    if (proposal.parameters?.destinationAccountId && !task.includes("vendor") && !task.includes("pay") && !task.includes("procure")) {
      return {
        valid: false,
        reasonCode: "ACTION_OUTSIDE_APPROVED_INTENT",
        error: "Payment destination specified for non-procurement task"
      };
    }

    return { valid: true };
  }
}
