/**
 * MORTAL 2.0 — Black Box Event Recorder
 * Records all evaluated actions, Sentinel decisions, and execution results
 * into an immutable cryptographic hash chain.
 */

import { randomUUID } from "node:crypto";
import type {
  BlackBoxEvent,
  ActionProposal,
  DecisionType,
  ReasonCode,
  X402PaymentResult
} from "../../types/index.ts";
import { DatabaseService } from "../db/database.ts";
import { HashChain, GENESIS_HASH } from "./HashChain.ts";
import { IncidentManager } from "./IncidentManager.ts";

export interface RecordDecisionParams {
  proposal: ActionProposal;
  decision: DecisionType;
  reasonCodes: ReasonCode[];
  policyVersion: string;
  executionResult?: {
    success: boolean;
    output?: any;
    error?: string;
  };
  paymentResult?: X402PaymentResult;
  humanApproval?: {
    approvedBy: string;
    approvedAt: number;
    notes?: string;
  };
}

export class EventRecorder {
  private db: DatabaseService;
  private incidentManager: IncidentManager;

  constructor(db: DatabaseService, incidentManager: IncidentManager) {
    this.db = db;
    this.incidentManager = incidentManager;
  }

  /**
   * Sanitizes proposed action parameters to ensure sensitive private keys
   * or credential tokens do not persist on-ledger.
   */
  private sanitizeParameters(params: Record<string, any>): Record<string, any> {
    const clean: Record<string, any> = {};
    for (const [k, v] of Object.entries(params)) {
      if (k.toLowerCase().includes("key") || k.toLowerCase().includes("secret") || k.toLowerCase().includes("password")) {
        clean[k] = "[REDACTED_FOR_SECURITY]";
      } else {
        clean[k] = v;
      }
    }
    return clean;
  }

  /**
   * Records an evaluated action into the Black Box hash chain.
   */
  public recordDecision(params: RecordDecisionParams): BlackBoxEvent {
    const latestEvent = this.db.getLatestEvent();
    const prevHash = latestEvent ? latestEvent.hash : GENESIS_HASH;
    const sequenceNumber = latestEvent ? latestEvent.sequenceNumber + 1 : 1;
    const now = Math.floor(Date.now() / 1000);
    const eventId = "evt_" + randomUUID();

    const sanitizedParams = this.sanitizeParameters(params.proposal.parameters || {});

    const proposedAction = {
      tool: params.proposal.tool,
      resource: params.proposal.resource,
      parameters: sanitizedParams
    };

    const hash = HashChain.computeEventHash(prevHash, {
      eventId,
      timestamp: now,
      agentEnsName: params.proposal.agentEnsName,
      approvedIntent: params.proposal.intentToken.targetTask,
      policyVersion: params.policyVersion,
      proposedAction,
      decision: params.decision,
      reasonCodes: params.reasonCodes
    });

    let paymentReference: BlackBoxEvent["paymentReference"] = undefined;
    if (params.paymentResult) {
      paymentReference = {
        scheme: "exact",
        network: "hedera:testnet",
        amountTinybars: params.paymentResult.amountTinybars,
        demoAmount: params.proposal.parameters?.demoAmount || 0,
        destinationAccountId: params.paymentResult.payTo,
        transactionId: params.paymentResult.transactionId,
        hashscanUrl: params.paymentResult.hashscanUrl,
        isSimulated: params.paymentResult.isSimulated
      };
    }

    const event: BlackBoxEvent = {
      eventId,
      sequenceNumber,
      prevHash,
      hash,
      timestamp: now,
      agentEnsName: params.proposal.agentEnsName,
      approvedIntent: params.proposal.intentToken.targetTask,
      policyVersion: params.policyVersion,
      proposedAction,
      decision: params.decision,
      reasonCodes: params.reasonCodes,
      humanApproval: params.humanApproval,
      executionResult: params.executionResult,
      paymentReference
    };

    this.db.insertEvent(event);

    // If decision is BLOCK, immediately generate an incident record
    if (params.decision === "BLOCK") {
      this.incidentManager.createIncident({
        eventId,
        agentEnsName: params.proposal.agentEnsName,
        severity: params.reasonCodes.includes("DEST_NOT_ALLOWLISTED") || params.reasonCodes.includes("OVER_LIMIT") ? "HIGH" : "MEDIUM",
        reasonCodes: params.reasonCodes,
        description: `Sentinel BLOCK triggered on tool "${params.proposal.tool}": ${params.reasonCodes.join(", ")}`,
        evidenceHash: hash
      });
    }

    return event;
  }
}
