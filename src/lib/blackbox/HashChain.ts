/**
 * MORTAL 2.0 — Cryptographic Hash Chain Ledger
 * Implements deterministic canonical JSON serialization and SHA-256 hash chaining.
 * 
 * Formal Invariant:
 * H_0 = 0x0000000000000000000000000000000000000000000000000000000000000000
 * H_n = SHA-256(H_{n-1} || CanonicalJSON(Event_n))
 * 
 * WORDING RULE (Section 6):
 * Hashing proves records have not changed since commitment.
 * It does not prove the original data was truthful.
 */

import { createHash } from "node:crypto";
import type { BlackBoxEvent } from "../../types/index.ts";

export const GENESIS_HASH = "0x" + "00".repeat(32);

export class HashChain {
  /**
   * Deterministically stringifies an object with recursive lexicographical key sorting.
   */
  public static canonicalize(obj: any): string {
    if (obj === null || obj === undefined) {
      return "null";
    }
    if (typeof obj !== "object") {
      return JSON.stringify(obj);
    }
    if (Array.isArray(obj)) {
      return "[" + obj.map(item => HashChain.canonicalize(item)).join(",") + "]";
    }

    const sortedKeys = Object.keys(obj).sort();
    const parts = sortedKeys.map(key => {
      return `${JSON.stringify(key)}:${HashChain.canonicalize(obj[key])}`;
    });
    return "{" + parts.join(",") + "}";
  }

  /**
   * Computes the SHA-256 hash for a BlackBox event chained to the previous hash.
   */
  public static computeEventHash(
    prevHash: string,
    eventData: {
      eventId: string;
      timestamp: number;
      agentEnsName: string;
      approvedIntent: string;
      policyVersion: string;
      proposedAction: any;
      decision: string;
      reasonCodes: string[];
    }
  ): string {
    const canonicalPayload = HashChain.canonicalize({
      agentEnsName: eventData.agentEnsName,
      approvedIntent: eventData.approvedIntent,
      decision: eventData.decision,
      eventId: eventData.eventId,
      policyVersion: eventData.policyVersion,
      prevHash,
      proposedAction: eventData.proposedAction,
      reasonCodes: [...eventData.reasonCodes].sort(),
      timestamp: eventData.timestamp
    });

    const digest = createHash("sha256").update(canonicalPayload).digest("hex");
    return "0x" + digest;
  }
}
