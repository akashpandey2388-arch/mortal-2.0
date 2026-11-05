/**
 * MORTAL 2.0 — Evidence Verifier
 * Recomputes the SHA-256 hash chain, pinpoints the first tampered/modified record,
 * and validates against Hedera Consensus Service (HCS) commitments.
 * 
 * MANDATORY WORDING RULE (Brief Section 6):
 * Hashing proves records have not changed since commitment.
 * It does not prove the original data was truthful.
 */

import { DatabaseService } from "../db/database.ts";
import { HashChain, GENESIS_HASH } from "./HashChain.ts";
import type { BlackBoxEvent } from "../../types/index.ts";

export interface VerificationResult {
  verified: boolean;
  totalRecordsChecked: number;
  chainHeadHash: string;
  tamperedRecordIndex?: number;
  tamperedRecordId?: string;
  expectedHash?: string;
  actualHash?: string;
  discrepancyType?: "HASH_MISMATCH" | "PREV_HASH_BROKEN" | "SEQUENCE_GAP";
  hcsCommitmentMatch: boolean;
  hcsConsensusTimestamp?: string;
  hcsTopicId?: string;
  message: string;
  wordingNotice: string;
}

export class EvidenceVerifier {
  private db: DatabaseService;

  constructor(db: DatabaseService) {
    this.db = db;
  }

  /**
   * Recomputes the cryptographic hash chain from sequence 1 to head.
   * Detects and pinpoints the exact first altered record if tampering occurred.
   */
  public verifyLedgerIntegrity(): VerificationResult {
    const events = this.db.listEvents(10000);
    const wordingNotice = "Hashing proves records have not changed since commitment. It does not prove the original data was truthful.";

    if (events.length === 0) {
      return {
        verified: true,
        totalRecordsChecked: 0,
        chainHeadHash: GENESIS_HASH,
        hcsCommitmentMatch: true,
        message: "Black Box ledger is empty. Genesis state intact.",
        wordingNotice
      };
    }

    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < events.length; i++) {
      const event = events[i];

      // 1. Verify prevHash link
      if (event.prevHash !== expectedPrevHash) {
        return {
          verified: false,
          totalRecordsChecked: i,
          chainHeadHash: event.hash,
          tamperedRecordIndex: i + 1,
          tamperedRecordId: event.eventId,
          expectedHash: expectedPrevHash,
          actualHash: event.prevHash,
          discrepancyType: "PREV_HASH_BROKEN",
          hcsCommitmentMatch: false,
          message: `TAMPER DETECTED at sequence #${event.sequenceNumber} (Event ID: ${event.eventId}): Broken previous hash pointer.`,
          wordingNotice
        };
      }

      // 2. Recompute event hash over canonical payload
      const recomputedHash = HashChain.computeEventHash(expectedPrevHash, {
        eventId: event.eventId,
        timestamp: event.timestamp,
        agentEnsName: event.agentEnsName,
        approvedIntent: event.approvedIntent,
        policyVersion: event.policyVersion,
        proposedAction: event.proposedAction,
        decision: event.decision,
        reasonCodes: event.reasonCodes
      });

      if (recomputedHash !== event.hash) {
        return {
          verified: false,
          totalRecordsChecked: i,
          chainHeadHash: event.hash,
          tamperedRecordIndex: i + 1,
          tamperedRecordId: event.eventId,
          expectedHash: recomputedHash,
          actualHash: event.hash,
          discrepancyType: "HASH_MISMATCH",
          hcsCommitmentMatch: false,
          message: `TAMPER DETECTED at sequence #${event.sequenceNumber} (Event ID: ${event.eventId}): Payload content modified after hash calculation. Expected ${recomputedHash}, found ${event.hash}.`,
          wordingNotice
        };
      }

      expectedPrevHash = event.hash;
    }

    // 3. Compare latest head hash against latest HCS commitment
    const anchors = this.db.listHcsAnchors();
    let hcsCommitmentMatch = true;
    let hcsConsensusTimestamp: string | undefined;
    let hcsTopicId: string | undefined;

    if (anchors.length > 0) {
      const latestAnchor = anchors[0];
      hcsTopicId = latestAnchor.topic_id;
      hcsConsensusTimestamp = latestAnchor.consensus_timestamp;

      // Check if chain head matches anchor
      const chainHead = events[events.length - 1].hash;
      hcsCommitmentMatch = chainHead === latestAnchor.chain_head_hash;
    }

    return {
      verified: true,
      totalRecordsChecked: events.length,
      chainHeadHash: events[events.length - 1].hash,
      hcsCommitmentMatch,
      hcsConsensusTimestamp,
      hcsTopicId,
      message: `Ledger cryptographic integrity verified across ${events.length} records. Chain head hash valid.`,
      wordingNotice
    };
  }
}
