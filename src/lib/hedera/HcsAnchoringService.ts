/**
 * MORTAL 2.0 — Hedera Consensus Service (HCS) Anchoring Service
 * Anchors Black Box hash chain heads and incident evidence to an immutable HCS topic.
 */

import { DatabaseService } from "../db/database.ts";
import { HederaClient, type HcsSubmissionReceipt } from "./HederaClient.ts";
import { CONTRACTS } from "../../../config/contracts.ts";

export interface AnchorResult {
  anchored: boolean;
  topicId: string;
  sequenceNumber: number;
  consensusTimestamp: string;
  chainHeadHash: string;
  hashscanUrl: string;
  isSimulated: boolean;
}

export class HcsAnchoringService {
  private db: DatabaseService;
  private hederaClient: HederaClient;
  private topicId: string;
  private currentSequence: number;

  constructor(
    db: DatabaseService,
    hederaClient: HederaClient,
    topicId: string = process.env.HEDERA_HCS_TOPIC_ID || "0.0.889900"
  ) {
    this.db = db;
    this.hederaClient = hederaClient;
    this.topicId = topicId;
    this.currentSequence = 1;
  }

  public getTopicId(): string {
    return this.topicId;
  }

  /**
   * Anchors the current Black Box chain head hash to the HCS topic.
   */
  public async anchorChainHead(eventId?: string): Promise<AnchorResult | null> {
    const latestEvent = this.db.getLatestEvent();
    if (!latestEvent) {
      return null;
    }

    const targetEventId = eventId || latestEvent.eventId;
    const chainHeadHash = latestEvent.hash;
    const seq = this.currentSequence++;

    const payload = JSON.stringify({
      protocol: "MORTAL-2.0",
      action: "AUDIT_COMMITMENT",
      eventId: targetEventId,
      chainHeadHash,
      sequenceNumber: latestEvent.sequenceNumber,
      timestamp: Math.floor(Date.now() / 1000)
    });

    const receipt: HcsSubmissionReceipt = await this.hederaClient.submitHcsMessage(
      this.topicId,
      payload,
      seq
    );

    // Record in local HCS anchors table
    this.db.recordHcsAnchor(
      this.topicId,
      seq,
      receipt.consensusTimestamp,
      chainHeadHash,
      targetEventId,
      receipt.isSimulated
    );

    // Update event record with HCS anchor metadata
    this.db.updateEventHcsAnchor(targetEventId, {
      topicId: this.topicId,
      sequenceNumber: seq,
      consensusTimestamp: receipt.consensusTimestamp,
      isSimulated: receipt.isSimulated
    });

    return {
      anchored: true,
      topicId: this.topicId,
      sequenceNumber: seq,
      consensusTimestamp: receipt.consensusTimestamp,
      chainHeadHash,
      hashscanUrl: receipt.hashscanUrl,
      isSimulated: receipt.isSimulated
    };
  }
}
