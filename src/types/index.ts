/**
 * MORTAL 2.0 — Shared Domain Types & Interfaces
 */

export type AgentLifecycleStatus = "ACTIVE" | "REVOKED" | "EXPIRED" | "SUSPENDED";

export interface AgentIdentity {
  ensName: string; // e.g. "procurement.mortal-sentinel.eth"
  ownerAddress: string; // EVM address of controller
  role: string; // e.g. "Procurement Agent"
  status: AgentLifecycleStatus;
  expiryTimestamp: number; // Unix timestamp in seconds
  registeredAt: number;
  textRecords: Record<string, string>;
  isSimulated: boolean;
  delegationDepth?: number;
  parentEnsName?: string;
  allowedCapabilities?: string[];
}

export interface IntentToken {
  tokenId: string;
  agentEnsName: string;
  nonce: string;
  timestamp: number;
  targetTask: string;
  signature: string; // Cryptographic signature over canonical intent
  signerAddress: string;
}

export interface ActionProposal {
  actionId: string;
  agentEnsName: string;
  intentToken: IntentToken;
  tool: string;
  resource: string;
  parameters: {
    vendorId?: string;
    destinationAccountId?: string;
    demoAmount?: number; // In labelled demo INR units
    tinybars?: string;
    description?: string;
    filePath?: string;
    [key: string]: any;
  };
}

export type DecisionType = "ALLOW" | "BLOCK" | "HUMAN_APPROVAL";

export type ReasonCode =
  | "AUTH_SIGNATURE_INVALID"
  | "NONCE_REPLAYED"
  | "ENS_RESOLUTION_FAILED"
  | "OWNER_MISMATCH"
  | "AGENT_EXPIRED"
  | "AGENT_REVOKED"
  | "AGENT_INACTIVE"
  | "TOOL_NOT_PERMITTED"
  | "RESOURCE_NOT_PERMITTED"
  | "ACTION_OUTSIDE_APPROVED_INTENT"
  | "DELEGATION_DEPTH_EXCEEDED"
  | "CHILD_SCOPE_EXCEEDS_PARENT"
  | "PARENT_AGENT_REVOKED"
  | "DEST_NOT_ALLOWLISTED"
  | "OVER_LIMIT"
  | "PERIOD_SPENDING_LIMIT_EXCEEDED"
  | "FREQUENCY_LIMIT_EXCEEDED"
  | "RISK_ANOMALY_DETECTED"
  | "APPROVAL_REQUIRED_AMOUNT_THRESHOLD"
  | "POLICY_PASSED_ALLOW";

export interface SentinelDecision {
  decision: DecisionType;
  reasonCodes: ReasonCode[];
  policyVersion: string;
  eventId: string;
  timestamp: number;
  agentEnsName: string;
  tool: string;
  authorizedPaymentTicket?: string; // Single-use, short-lived gateway ticket only on ALLOW for payment
  auditTrail: {
    step: number;
    name: string;
    passed: boolean;
    reason?: string;
  }[];
}

export interface BlackBoxEvent {
  eventId: string;
  prevHash: string;
  hash: string;
  sequenceNumber: number;
  timestamp: number;
  agentEnsName: string;
  approvedIntent: string;
  policyVersion: string;
  proposedAction: {
    tool: string;
    resource: string;
    parameters: Record<string, any>; // Sensitive parameters redacted or hash-preserved
  };
  decision: DecisionType;
  reasonCodes: ReasonCode[];
  humanApproval?: {
    approvedBy: string;
    approvedAt: number;
    notes?: string;
  };
  executionResult?: {
    success: boolean;
    output?: any;
    error?: string;
  };
  paymentReference?: {
    scheme: string;
    network: string;
    amountTinybars: string;
    demoAmount: number;
    destinationAccountId: string;
    transactionId: string;
    hashscanUrl: string;
    isSimulated: boolean;
  };
  hcsAnchor?: {
    topicId: string;
    sequenceNumber: number;
    consensusTimestamp: string;
    isSimulated: boolean;
  };
}

export interface IncidentRecord {
  incidentId: string;
  eventId: string;
  agentEnsName: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reasonCodes: ReasonCode[];
  description: string;
  detectedAt: number;
  status: "OPEN" | "INVESTIGATING" | "RESOLVED";
  evidenceHash: string;
  hcsAnchor?: {
    topicId: string;
    sequenceNumber: number;
    consensusTimestamp: string;
  };
}

export interface X402PaymentRequirement {
  scheme: "exact";
  network: string; // e.g. "hedera:testnet"
  amount: string; // tinybars
  asset: "0.0.0";
  payTo: string; // Hedera account ID
  maxTimeoutSeconds: number;
  extra: {
    feePayer: string;
    assetTransferMethods: string[];
    demoAmount: number;
    demoCurrency: string;
  };
}

export interface X402PaymentPayload {
  x402Version: number;
  resource: {
    url: string;
    description: string;
    mimeType: string;
  };
  accepted: X402PaymentRequirement;
  payload: {
    transaction: string; // Base64 encoded Hedera transaction bytes
    signerAccountId: string;
  };
  authorizedTicket: string; // Must match Sentinel-issued single-use ticket
}

export interface X402PaymentResult {
  success: boolean;
  transactionId: string;
  consensusTimestamp: string;
  hashscanUrl: string;
  amountTinybars: string;
  payTo: string;
  payerAccountId: string;
  feePayerAccountId: string;
  isSimulated: boolean;
  error?: string;
}

export interface DelegationPassport {
  parentEnsName: string;
  childEnsName: string;
  delegatedCapabilities: string[]; // Must be subset of parent's capabilities
  depth: number;
  issuedAt: number;
  expiresAt: number;
  parentSignature: string;
  revoked: boolean;
}

export interface TrustPassport {
  agentEnsName: string;
  totalEvaluatedActions: number;
  allowedActionsCount: number;
  blockedIncidentsCount: number;
  humanApprovalsCount: number;
  firstActivityTimestamp: number;
  latestActivityTimestamp: number;
  verifiedHcsAnchorsCount: number;
  reliabilityRatio: number; // calculated ratio, strictly evidence-based
  isSimulated: boolean;
}
