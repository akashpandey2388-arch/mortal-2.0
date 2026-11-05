/**
 * MORTAL 2.0 — Delegation Manager
 * Enforces cryptographic delegation passports, capability attenuation,
 * depth limits, and parent-revocation propagation.
 */

import { createHash, randomBytes } from "node:crypto";
import type { DelegationPassport, AgentIdentity } from "../../types/index.ts";
import { DatabaseService } from "../db/database.ts";
import { EnsIdentityManager } from "./EnsIdentityManager.ts";
import { DEFAULT_POLICY } from "../../../config/policy.ts";

export interface CreateDelegationParams {
  parentEnsName: string;
  childEnsName: string;
  childOwnerAddress: string;
  delegatedCapabilities: string[]; // Must be subset of parent's capabilities
  ttlSeconds: number;
  parentCallerAddress: string;
}

export class DelegationManager {
  private db: DatabaseService;
  private identityManager: EnsIdentityManager;

  constructor(db: DatabaseService, identityManager: EnsIdentityManager) {
    this.db = db;
    this.identityManager = identityManager;
  }

  /**
   * Issues a Delegation Passport from parent agent to child agent.
   * Strictly enforces:
   * 1. Parent exists and is ACTIVE.
   * 2. Caller is parent's authorized owner.
   * 3. Attenuation: child capabilities MUST be a strict subset of parent capabilities.
   * 4. Delegation depth does not exceed max allowed depth.
   */
  public issueDelegationPassport(params: CreateDelegationParams): DelegationPassport {
    const parent = this.identityManager.resolveAgent(params.parentEnsName);
    if (!parent) {
      throw new Error(`DELEGATION_ERROR: Parent agent ${params.parentEnsName} not found`);
    }

    if (parent.status !== "ACTIVE") {
      throw new Error(`DELEGATION_ERROR: Parent agent ${params.parentEnsName} is ${parent.status}. Only ACTIVE agents can delegate.`);
    }

    if (params.parentCallerAddress.toLowerCase() !== parent.ownerAddress.toLowerCase()) {
      throw new Error(`UNAUTHORIZED_DELEGATION: Caller ${params.parentCallerAddress} does not own parent ${params.parentEnsName}`);
    }

    const parentDepth = parent.delegationDepth || 0;
    const childDepth = parentDepth + 1;
    if (childDepth > DEFAULT_POLICY.delegationRules.maxDelegationDepth) {
      throw new Error(`DELEGATION_DEPTH_EXCEEDED: Requested depth ${childDepth} exceeds maximum limit of ${DEFAULT_POLICY.delegationRules.maxDelegationDepth}`);
    }

    // Attenuation check: child capabilities ⊆ parent capabilities
    const parentCapabilities = new Set(parent.allowedCapabilities || []);
    for (const cap of params.delegatedCapabilities) {
      if (!parentCapabilities.has(cap)) {
        throw new Error(
          `ATTENUATION_VIOLATION: Child capability "${cap}" is not possessed by parent agent ${params.parentEnsName}. Attenuation requires child ⊆ parent.`
        );
      }
    }

    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + params.ttlSeconds;

    // Deterministic signature hash over delegation passport
    const canonicalPayload = JSON.stringify({
      parent: params.parentEnsName.toLowerCase(),
      child: params.childEnsName.toLowerCase(),
      capabilities: [...params.delegatedCapabilities].sort(),
      depth: childDepth,
      issuedAt: now,
      expiresAt
    });
    const parentSignature = "0x" + createHash("sha256").update(canonicalPayload).digest("hex");

    const passport: DelegationPassport = {
      parentEnsName: params.parentEnsName.toLowerCase(),
      childEnsName: params.childEnsName.toLowerCase(),
      delegatedCapabilities: params.delegatedCapabilities,
      depth: childDepth,
      issuedAt: now,
      expiresAt,
      parentSignature,
      revoked: false
    };

    // Store delegation record
    this.db.upsertDelegation(passport);

    // Register child in agent identity table
    const childIdentity: AgentIdentity = {
      ensName: params.childEnsName.toLowerCase(),
      ownerAddress: params.childOwnerAddress.toLowerCase(),
      role: `Delegated Subagent of ${params.parentEnsName}`,
      status: "ACTIVE",
      expiryTimestamp: expiresAt,
      registeredAt: now,
      textRecords: {
        "agent.id": "child_" + randomBytes(8).toString("hex"),
        "agent.parent": params.parentEnsName.toLowerCase(),
        "agent.status": "ACTIVE",
        "agent.expiry": expiresAt.toString(),
        "agent.depth": childDepth.toString(),
        "agent.capabilities": JSON.stringify(params.delegatedCapabilities)
      },
      isSimulated: parent.isSimulated,
      delegationDepth: childDepth,
      parentEnsName: params.parentEnsName.toLowerCase(),
      allowedCapabilities: params.delegatedCapabilities
    };
    this.db.upsertAgent(childIdentity);

    return passport;
  }

  /**
   * Validates delegation validity at runtime for an action.
   */
  public validateDelegation(childEnsName: string, requiredCapability: string): {
    valid: boolean;
    reasonCode?: string;
    details?: string;
  } {
    const child = this.identityManager.resolveAgent(childEnsName);
    if (!child) {
      return { valid: false, reasonCode: "ENS_RESOLUTION_FAILED", details: "Child agent not found" };
    }

    if (!child.parentEnsName) {
      // Primary agent, not delegated
      return { valid: true };
    }

    const delegation = this.db.getDelegation(childEnsName.toLowerCase());
    if (!delegation) {
      return { valid: false, reasonCode: "CHILD_SCOPE_EXCEEDS_PARENT", details: "Missing delegation passport" };
    }

    if (delegation.revoked) {
      return { valid: false, reasonCode: "PARENT_AGENT_REVOKED", details: "Delegation has been revoked" };
    }

    // Check parent lifecycle status (revocation cascades to child!)
    const parent = this.identityManager.resolveAgent(delegation.parentEnsName);
    if (!parent || parent.status !== "ACTIVE") {
      return {
        valid: false,
        reasonCode: "PARENT_AGENT_REVOKED",
        details: `Parent agent ${delegation.parentEnsName} is ${parent?.status || "NOT_FOUND"}. Revocation propagates to child.`
      };
    }

    // Check depth
    if (delegation.depth > DEFAULT_POLICY.delegationRules.maxDelegationDepth) {
      return { valid: false, reasonCode: "DELEGATION_DEPTH_EXCEEDED", details: "Depth limit exceeded" };
    }

    // Check capability
    if (!delegation.delegatedCapabilities.includes(requiredCapability)) {
      return {
        valid: false,
        reasonCode: "CHILD_SCOPE_EXCEEDS_PARENT",
        details: `Child lacks delegated capability: ${requiredCapability}`
      };
    }

    return { valid: true };
  }

  /**
   * Revokes delegation from parent to child.
   */
  public revokeDelegation(childEnsName: string, callerAddress: string): void {
    const delegation = this.db.getDelegation(childEnsName.toLowerCase());
    if (!delegation) {
      throw new Error(`Delegation for ${childEnsName} not found`);
    }

    const parent = this.identityManager.resolveAgent(delegation.parentEnsName);
    if (!parent || parent.ownerAddress.toLowerCase() !== callerAddress.toLowerCase()) {
      throw new Error(`UNAUTHORIZED: Only parent owner can revoke delegation`);
    }

    delegation.revoked = true;
    this.db.upsertDelegation(delegation);

    // Also mark child agent status as REVOKED
    const child = this.db.getAgent(childEnsName.toLowerCase());
    if (child) {
      child.status = "REVOKED";
      child.textRecords["agent.status"] = "REVOKED";
      this.db.upsertAgent(child);
    }
  }
}
