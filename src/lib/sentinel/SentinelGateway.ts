/**
 * MORTAL 2.0 — Sentinel Authorization Gateway
 * The central gatekeeper enforcing the 10-step deterministic policy pipeline in exact order.
 * 
 * CORE INVARIANT:
 * Every sensitive action must pass through Sentinel.
 * A frontend decision or LLM output can NEVER override a deterministic denial.
 * Payment services are strictly unreachable without a gateway-issued, single-use, short-lived authorization ticket.
 */

import { randomUUID } from "node:crypto";
import type {
  ActionProposal,
  SentinelDecision,
  ReasonCode,
  DecisionType
} from "../../types/index.ts";
import { DEFAULT_POLICY, type PolicyConfig } from "../../../config/policy.ts";
import { DatabaseService } from "../db/database.ts";
import { EnsIdentityManager } from "../identity/EnsIdentityManager.ts";
import { DelegationManager } from "../identity/DelegationManager.ts";
import { IntentValidator } from "./IntentValidator.ts";
import { CapabilityManager } from "./CapabilityManager.ts";
import { PolicyEngine } from "./PolicyEngine.ts";
import { RiskEngine } from "./RiskEngine.ts";
import { EventRecorder } from "../blackbox/EventRecorder.ts";
import { demoUnitsToTinybars } from "../../../config/currency.ts";

export class SentinelGateway {
  private db: DatabaseService;
  private identityManager: EnsIdentityManager;
  private delegationManager: DelegationManager;
  private intentValidator: IntentValidator;
  private capabilityManager: CapabilityManager;
  private policyEngine: PolicyEngine;
  private riskEngine: RiskEngine;
  private eventRecorder: EventRecorder;
  private policy: PolicyConfig;

  constructor(
    db: DatabaseService,
    identityManager: EnsIdentityManager,
    delegationManager: DelegationManager,
    eventRecorder: EventRecorder,
    policy: PolicyConfig = DEFAULT_POLICY
  ) {
    this.db = db;
    this.identityManager = identityManager;
    this.delegationManager = delegationManager;
    this.eventRecorder = eventRecorder;
    this.policy = policy;

    this.intentValidator = new IntentValidator(db);
    this.capabilityManager = new CapabilityManager(policy);
    this.policyEngine = new PolicyEngine(db, policy);
    this.riskEngine = new RiskEngine();
  }

  /**
   * Evaluates an action proposal against the 10-step deterministic pipeline.
   * Every decision (ALLOW, BLOCK, HUMAN_APPROVAL) is immutably written to the Black Box ledger.
   */
  public evaluateAction(proposal: ActionProposal): SentinelDecision {
    const auditTrail: SentinelDecision["auditTrail"] = [];
    const reasonCodes: ReasonCode[] = [];
    let decision: DecisionType = "ALLOW";
    let authorizedPaymentTicket: string | undefined = undefined;
    const now = Math.floor(Date.now() / 1000);

    // =========================================================================
    // STEP 1: Signature/intent token valid and not replayed (nonce store; duplicate -> BLOCK)
    // =========================================================================
    const tokenResult = this.intentValidator.validateIntentToken(proposal.intentToken);
    if (!tokenResult.valid) {
      decision = "BLOCK";
      reasonCodes.push(tokenResult.reasonCode || "AUTH_SIGNATURE_INVALID");
      auditTrail.push({
        step: 1,
        name: "Intent Token & Nonce Validation",
        passed: false,
        reason: tokenResult.error
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }
    auditTrail.push({ step: 1, name: "Intent Token & Nonce Validation", passed: true });

    // =========================================================================
    // STEP 2: Agent identity resolves via ENS; owner matches registry
    // =========================================================================
    const agent = this.identityManager.resolveAgent(proposal.agentEnsName);
    if (!agent) {
      decision = "BLOCK";
      reasonCodes.push("ENS_RESOLUTION_FAILED");
      auditTrail.push({
        step: 2,
        name: "ENS Identity & Owner Resolution",
        passed: false,
        reason: `ENS name "${proposal.agentEnsName}" does not resolve to an active identity`
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }

    if (proposal.intentToken.signerAddress.toLowerCase() !== agent.ownerAddress.toLowerCase()) {
      decision = "BLOCK";
      reasonCodes.push("OWNER_MISMATCH");
      auditTrail.push({
        step: 2,
        name: "ENS Identity & Owner Resolution",
        passed: false,
        reason: `Signer ${proposal.intentToken.signerAddress} does not match ENS owner ${agent.ownerAddress}`
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }
    auditTrail.push({ step: 2, name: "ENS Identity & Owner Resolution", passed: true });

    // =========================================================================
    // STEP 3: Lifecycle status ACTIVE; not revoked; not expired
    // =========================================================================
    if (agent.status === "REVOKED") {
      decision = "BLOCK";
      reasonCodes.push("AGENT_REVOKED");
      auditTrail.push({
        step: 3,
        name: "Agent Lifecycle Status",
        passed: false,
        reason: `Agent identity ${agent.ensName} is REVOKED`
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }

    if (agent.status === "EXPIRED" || now > agent.expiryTimestamp) {
      decision = "BLOCK";
      reasonCodes.push("AGENT_EXPIRED");
      auditTrail.push({
        step: 3,
        name: "Agent Lifecycle Status",
        passed: false,
        reason: `Agent identity ${agent.ensName} expired at timestamp ${agent.expiryTimestamp}`
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }

    if (agent.status !== "ACTIVE") {
      decision = "BLOCK";
      reasonCodes.push("AGENT_INACTIVE");
      auditTrail.push({
        step: 3,
        name: "Agent Lifecycle Status",
        passed: false,
        reason: `Agent status is ${agent.status}`
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }
    auditTrail.push({ step: 3, name: "Agent Lifecycle Status", passed: true });

    // =========================================================================
    // STEP 4: Tool is in allowed tools; resource is in allowed resources
    // =========================================================================
    const toolResult = this.capabilityManager.checkTool(proposal.tool);
    if (!toolResult.passed) {
      decision = "BLOCK";
      reasonCodes.push(toolResult.reasonCode || "TOOL_NOT_PERMITTED");
      auditTrail.push({
        step: 4,
        name: "Tool & Resource Capability Checks",
        passed: false,
        reason: toolResult.error
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }

    const resourceResult = this.capabilityManager.checkResource(proposal.resource);
    if (!resourceResult.passed) {
      decision = "BLOCK";
      reasonCodes.push(resourceResult.reasonCode || "RESOURCE_NOT_PERMITTED");
      auditTrail.push({
        step: 4,
        name: "Tool & Resource Capability Checks",
        passed: false,
        reason: resourceResult.error
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }
    auditTrail.push({ step: 4, name: "Tool & Resource Capability Checks", passed: true });

    // =========================================================================
    // STEP 5: Action is within the approved task/intent
    // =========================================================================
    const taskResult = this.intentValidator.validateActionWithinIntent(proposal);
    if (!taskResult.valid) {
      decision = "BLOCK";
      reasonCodes.push(taskResult.reasonCode || "ACTION_OUTSIDE_APPROVED_INTENT");
      auditTrail.push({
        step: 5,
        name: "Intent & Task Scope Alignment",
        passed: false,
        reason: taskResult.error
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }
    auditTrail.push({ step: 5, name: "Intent & Task Scope Alignment", passed: true });

    // =========================================================================
    // STEP 6: Delegation checks: child scope ⊆ parent scope, depth limit, parent still active
    // =========================================================================
    if (agent.parentEnsName) {
      const delegationCheck = this.delegationManager.validateDelegation(agent.ensName, proposal.tool);
      if (!delegationCheck.valid) {
        decision = "BLOCK";
        reasonCodes.push((delegationCheck.reasonCode as ReasonCode) || "CHILD_SCOPE_EXCEEDS_PARENT");
        auditTrail.push({
          step: 6,
          name: "Delegation Passport & Scope Attenuation",
          passed: false,
          reason: delegationCheck.details
        });
        return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
      }

      // Check if child is attempting parent-only payment
      if (proposal.tool === "execute_vendor_payment" && !this.policy.delegationRules.allowPaymentDelegation) {
        decision = "BLOCK";
        reasonCodes.push("CHILD_SCOPE_EXCEEDS_PARENT");
        auditTrail.push({
          step: 6,
          name: "Delegation Passport & Scope Attenuation",
          passed: false,
          reason: "Payment tool is parent-only; delegation rules forbid child agent payments"
        });
        return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
      }
    }
    auditTrail.push({ step: 6, name: "Delegation Passport & Scope Attenuation", passed: true });

    // =========================================================================
    // STEP 7: Payment checks: destination allowlist, max per payment, period spend, frequency
    // =========================================================================
    let paymentRequiresHumanApproval = false;
    if (proposal.tool === "execute_vendor_payment") {
      const paymentCheck = this.policyEngine.evaluatePaymentPolicy(proposal);
      if (!paymentCheck.passed) {
        decision = "BLOCK";
        reasonCodes.push(...paymentCheck.reasonCodes);
        auditTrail.push({
          step: 7,
          name: "Payment Policy & Spending Limits",
          passed: false,
          reason: paymentCheck.errors.join("; ")
        });
        return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
      }

      if (paymentCheck.requiresHumanApproval) {
        paymentRequiresHumanApproval = true;
      }
      auditTrail.push({ step: 7, name: "Payment Policy & Spending Limits", passed: true });
    } else {
      auditTrail.push({ step: 7, name: "Payment Policy & Spending Limits", passed: true, reason: "Non-payment tool" });
    }

    // =========================================================================
    // STEP 8: Risk engine (rule-based; LLM signal can only ADD caution -> HUMAN_APPROVAL)
    // =========================================================================
    const riskResult = this.riskEngine.evaluateRisk(proposal);
    let riskElevated = false;
    if (riskResult.recommendedElevation === "HUMAN_APPROVAL") {
      riskElevated = true;
      reasonCodes.push(riskResult.reasonCode || "RISK_ANOMALY_DETECTED");
      auditTrail.push({
        step: 8,
        name: "Risk Engine & Behavioral Anomaly Check",
        passed: true,
        reason: `Risk score elevated (${riskResult.riskScore}/100): ${riskResult.anomaliesDetected.join(", ")}`
      });
    } else {
      auditTrail.push({ step: 8, name: "Risk Engine & Behavioral Anomaly Check", passed: true });
    }

    // =========================================================================
    // STEP 9: Amount > configurable approval threshold -> HUMAN_APPROVAL
    // =========================================================================
    if (paymentRequiresHumanApproval || riskElevated) {
      decision = "HUMAN_APPROVAL";
      if (paymentRequiresHumanApproval && !reasonCodes.includes("APPROVAL_REQUIRED_AMOUNT_THRESHOLD")) {
        reasonCodes.push("APPROVAL_REQUIRED_AMOUNT_THRESHOLD");
      }
      auditTrail.push({
        step: 9,
        name: "Human Approval Threshold Evaluation",
        passed: false,
        reason: "Action routed to Human Approval Queue"
      });
      return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail);
    }
    auditTrail.push({ step: 9, name: "Human Approval Threshold Evaluation", passed: true });

    // =========================================================================
    // STEP 10: Otherwise ALLOW
    // =========================================================================
    decision = "ALLOW";
    reasonCodes.push("POLICY_PASSED_ALLOW");
    auditTrail.push({ step: 10, name: "Final Sentinel Decision", passed: true, reason: "ALLOW" });

    // If payment action is ALLOWed, issue single-use authorization ticket
    if (proposal.tool === "execute_vendor_payment") {
      const ticketId = "ticket_" + randomUUID();
      const demoAmount = proposal.parameters?.demoAmount || 0;
      const tinybars = demoUnitsToTinybars(demoAmount).toString();
      const dest = proposal.parameters?.destinationAccountId || "";

      this.db.issuePaymentTicket(ticketId, proposal.agentEnsName, proposal.actionId, dest, tinybars, 300);
      authorizedPaymentTicket = ticketId;
    }

    return this.finalizeDecision(proposal, decision, reasonCodes, auditTrail, authorizedPaymentTicket);
  }

  /**
   * Finalizes decision, writes event to Black Box, and returns response.
   */
  private finalizeDecision(
    proposal: ActionProposal,
    decision: DecisionType,
    reasonCodes: ReasonCode[],
    auditTrail: SentinelDecision["auditTrail"],
    authorizedPaymentTicket?: string
  ): SentinelDecision {
    const recordedEvent = this.eventRecorder.recordDecision({
      proposal,
      decision,
      reasonCodes,
      policyVersion: this.policy.policyVersion
    });

    return {
      decision,
      reasonCodes,
      policyVersion: this.policy.policyVersion,
      eventId: recordedEvent.eventId,
      timestamp: recordedEvent.timestamp,
      agentEnsName: proposal.agentEnsName,
      tool: proposal.tool,
      authorizedPaymentTicket,
      auditTrail
    };
  }
}
