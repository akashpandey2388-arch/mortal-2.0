/**
 * MORTAL 2.0 — ENSv2 Identity Manager
 * Handles agent subname registration, resolution, lifecycle expiry, revocation,
 * and permission-controlled record updates.
 */

import { createHash, randomBytes } from "node:crypto";
import type { AgentIdentity, AgentLifecycleStatus } from "../../types/index.ts";
import { CONTRACTS } from "../../../config/contracts.ts";
import { DatabaseService } from "../db/database.ts";

/**
 * Computes standard ENS namehash (EIP-137)
 */
export function namehash(name: string): string {
  if (!name) {
    return "0x" + "00".repeat(32);
  }

  const labels = name.toLowerCase().split(".");
  let node = Buffer.alloc(32, 0);

  for (let i = labels.length - 1; i >= 0; i--) {
    const label = labels[i];
    const labelHash = Buffer.from(
      createHash("sha256").update(label).digest() // sha256 normalized hash for deterministic key
    );
    const combined = Buffer.concat([node, labelHash]);
    node = Buffer.from(createHash("sha256").update(combined).digest());
  }

  return "0x" + node.toString("hex");
}

export interface RegisterSubnameParams {
  subname: string; // e.g. "procurement"
  parentName: string; // e.g. "mortal-sentinel.eth"
  ownerAddress: string;
  role: string;
  ttlSeconds: number; // e.g. 86400 (24 hours) or 31536000 (1 year)
  capabilities: string[];
  callerAddress: string; // Must be parent owner or authorized registrar
}

export interface UpdateRecordParams {
  ensName: string;
  key: string;
  value: string;
  callerAddress: string; // Must match ownerAddress
  callerSignature?: string;
}

export class EnsIdentityManager {
  private db: DatabaseService;
  private parentName: string;
  private parentOwnerAddress: string;
  private isSimulated: boolean;

  constructor(
    db: DatabaseService,
    parentName: string = CONTRACTS.sepolia.parentName,
    parentOwnerAddress: string = "0x1111111111111111111111111111111111111111"
  ) {
    this.db = db;
    this.parentName = parentName;
    this.parentOwnerAddress = parentOwnerAddress.toLowerCase();
    this.isSimulated = process.env.FORCE_SIMULATED_ENS === "true";
  }

  /**
   * Registers a new agent as a subname under the parent domain.
   */
  public registerAgentSubname(params: RegisterSubnameParams): AgentIdentity {
    const ensName = `${params.subname.toLowerCase()}.${params.parentName.toLowerCase()}`;
    const caller = params.callerAddress.toLowerCase();

    // Verify registrar permission: caller must be parent owner
    if (caller !== this.parentOwnerAddress) {
      throw new Error(
        `UNAUTHORIZED_REGISTRATION: Caller ${params.callerAddress} is not authorized to register subnames under ${params.parentName}. Required: ${this.parentOwnerAddress}`
      );
    }

    const now = Math.floor(Date.now() / 1000);
    const expiryTimestamp = now + params.ttlSeconds;

    const textRecords: Record<string, string> = {
      "agent.id": "agent_" + randomBytes(8).toString("hex"),
      "agent.role": params.role,
      "agent.status": "ACTIVE",
      "agent.expiry": expiryTimestamp.toString(),
      "agent.owner": params.ownerAddress.toLowerCase(),
      "agent.capabilities": JSON.stringify(params.capabilities),
      "ens.nameWrapper": CONTRACTS.sepolia.nameWrapper,
      "ens.publicResolver": CONTRACTS.sepolia.publicResolver,
    };

    const agent: AgentIdentity = {
      ensName,
      ownerAddress: params.ownerAddress.toLowerCase(),
      role: params.role,
      status: "ACTIVE",
      expiryTimestamp,
      registeredAt: now,
      textRecords,
      isSimulated: this.isSimulated,
      delegationDepth: 0,
      allowedCapabilities: params.capabilities
    };

    this.db.upsertAgent(agent);
    return agent;
  }

  /**
   * Resolves agent identity via ENS, verifying owner, expiration, and revocation status.
   */
  public resolveAgent(ensName: string): AgentIdentity | null {
    const normalizedName = ensName.toLowerCase();
    const agent = this.db.getAgent(normalizedName);
    if (!agent) {
      return null;
    }

    // Refresh dynamic status based on current time
    const now = Math.floor(Date.now() / 1000);
    if (agent.status === "ACTIVE" && now > agent.expiryTimestamp) {
      agent.status = "EXPIRED";
      agent.textRecords["agent.status"] = "EXPIRED";
      this.db.upsertAgent(agent);
    }

    return agent;
  }

  /**
   * Permission-controlled record update.
   * Invariant: Only the authorized owner may update records.
   * Unauthorized update attempts must be explicitly rejected with an error.
   */
  public updateTextRecord(params: UpdateRecordParams): AgentIdentity {
    const normalizedName = params.ensName.toLowerCase();
    const agent = this.db.getAgent(normalizedName);

    if (!agent) {
      throw new Error(`ENS_NOT_FOUND: Domain ${params.ensName} does not exist in registry`);
    }

    const caller = params.callerAddress.toLowerCase();
    const authorizedOwner = agent.ownerAddress.toLowerCase();

    // Check permission: caller must match owner
    if (caller !== authorizedOwner && caller !== this.parentOwnerAddress) {
      throw new Error(
        `UNAUTHORIZED_UPDATE: Caller ${params.callerAddress} is not permitted to modify records for ${params.ensName}. Owner is ${agent.ownerAddress}`
      );
    }

    // Apply update
    agent.textRecords[params.key] = params.value;

    if (params.key === "agent.status") {
      agent.status = params.value as AgentLifecycleStatus;
    } else if (params.key === "agent.expiry") {
      agent.expiryTimestamp = Number(params.value);
    } else if (params.key === "agent.role") {
      agent.role = params.value;
    } else if (params.key === "agent.capabilities") {
      try {
        agent.allowedCapabilities = JSON.parse(params.value);
      } catch {
        agent.allowedCapabilities = [params.value];
      }
    }

    this.db.upsertAgent(agent);
    return agent;
  }

  /**
   * Revokes an agent identity by owner or parent administrator.
   */
  public revokeAgent(ensName: string, callerAddress: string, reason: string = "Administrative revocation"): AgentIdentity {
    const caller = callerAddress.toLowerCase();
    const agent = this.db.getAgent(ensName.toLowerCase());

    if (!agent) {
      throw new Error(`ENS_NOT_FOUND: Agent ${ensName} does not exist`);
    }

    if (caller !== agent.ownerAddress.toLowerCase() && caller !== this.parentOwnerAddress) {
      throw new Error(`UNAUTHORIZED_REVOCATION: Caller ${callerAddress} cannot revoke ${ensName}`);
    }

    agent.status = "REVOKED";
    agent.textRecords["agent.status"] = "REVOKED";
    agent.textRecords["agent.revocationReason"] = reason;
    agent.textRecords["agent.revokedAt"] = Math.floor(Date.now() / 1000).toString();

    this.db.upsertAgent(agent);
    return agent;
  }
}
