/**
 * MORTAL 2.0 — Comprehensive Verification Suite
 * Implements all 14 required tests specified in Section 9 of the brief.
 * 
 * 1. Valid agent + permitted action
 * 2. Over limit
 * 3. Unknown destination
 * 4. Expired identity
 * 5. Revoked agent
 * 6. Child attempting parent-only payment
 * 7. Duplicate token/replay
 * 8. Unauthorized tool
 * 9. Approval-required action
 * 10. Tampered evidence
 * 11. Failed x402 payment
 * 12. Successful x402 payment
 * 13. Successful evidence verification
 * 14. Hedera unavailable / graceful simulation fallback
 * CRITICAL: Payment service is NOT invoked when Sentinel blocks
 * TRACK A: Unauthorized ENS record update is rejected
 */

import test from "node:test";
import assert from "node:assert";
import { randomBytes, randomUUID } from "node:crypto";

import { DatabaseService } from "../src/lib/db/database.ts";
import { EnsIdentityManager } from "../src/lib/identity/EnsIdentityManager.ts";
import { DelegationManager } from "../src/lib/identity/DelegationManager.ts";
import { SentinelGateway } from "../src/lib/sentinel/SentinelGateway.ts";
import { EventRecorder } from "../src/lib/blackbox/EventRecorder.ts";
import { IncidentManager } from "../src/lib/blackbox/IncidentManager.ts";
import { EvidenceVerifier } from "../src/lib/blackbox/EvidenceVerifier.ts";
import { HederaClient } from "../src/lib/hedera/HederaClient.ts";
import { HcsAnchoringService } from "../src/lib/hedera/HcsAnchoringService.ts";
import { X402PaymentService } from "../src/lib/hedera/X402PaymentService.ts";
import { IntentValidator } from "../src/lib/sentinel/IntentValidator.ts";
import { TrustPassportManager } from "../src/lib/identity/TrustPassportManager.ts";
import type { ActionProposal, IntentToken } from "../src/types/index.ts";

function setupEnvironment() {
  const db = new DatabaseService(":memory:");
  const ens = new EnsIdentityManager(db, "mortal-sentinel.eth", "0x1111111111111111111111111111111111111111");
  const delegation = new DelegationManager(db, ens);
  const incidentMgr = new IncidentManager(db);
  const eventRecorder = new EventRecorder(db, incidentMgr);
  const sentinel = new SentinelGateway(db, ens, delegation, eventRecorder);
  const verifier = new EvidenceVerifier(db);
  const hedera = new HederaClient("testnet", "0.0.123456", "");
  const hcs = new HcsAnchoringService(db, hedera, "0.0.889900");
  const payment = new X402PaymentService(db, hedera, "0.0.567890", "0.0.123456");
  const trustMgr = new TrustPassportManager(db);

  // Register primary procurement agent
  const primaryOwner = "0x2222222222222222222222222222222222222222";
  const agent = ens.registerAgentSubname({
    subname: "procurement",
    parentName: "mortal-sentinel.eth",
    ownerAddress: primaryOwner,
    role: "Autonomous Procurement Agent",
    ttlSeconds: 86400,
    capabilities: [
      "read_approved_file",
      "create_procurement_report",
      "execute_vendor_payment",
      "query_inventory"
    ],
    callerAddress: "0x1111111111111111111111111111111111111111" // Parent owner
  });

  function createSignedProposal(
    tool: string,
    resource: string,
    task: string,
    params: any,
    agentEnsName: string = agent.ensName,
    signerAddress: string = primaryOwner
  ): ActionProposal {
    const nonce = "nonce_" + randomBytes(8).toString("hex");
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = IntentValidator.computeIntentHash(agentEnsName, nonce, timestamp, task);

    const intentToken: IntentToken = {
      tokenId: "tok_" + randomUUID(),
      agentEnsName,
      nonce,
      timestamp,
      targetTask: task,
      signature,
      signerAddress
    };

    return {
      actionId: "act_" + randomUUID(),
      agentEnsName,
      intentToken,
      tool,
      resource,
      parameters: params
    };
  }

  return {
    db,
    ens,
    delegation,
    incidentMgr,
    eventRecorder,
    sentinel,
    verifier,
    hedera,
    hcs,
    payment,
    trustMgr,
    agent,
    primaryOwner,
    createSignedProposal
  };
}

test("1. Valid agent + permitted action -> ALLOW", () => {
  const env = setupEnvironment();
  const proposal = env.createSignedProposal(
    "read_approved_file",
    "internal://procurement/orders/order_101.json",
    "procure supplies for warehouse inventory",
    { filePath: "/procurement/orders/order_101.json" }
  );

  const decision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(decision.decision, "ALLOW");
  assert.ok(decision.reasonCodes.includes("POLICY_PASSED_ALLOW"));
  assert.ok(decision.eventId.startsWith("evt_"));

  // Verify recorded in Black Box
  const event = env.db.getEventById(decision.eventId);
  assert.ok(event);
  assert.strictEqual(event?.decision, "ALLOW");
});

test("2. Over limit -> BLOCK (₹50,000 exceeds ₹5,000 max)", () => {
  const env = setupEnvironment();
  const proposal = env.createSignedProposal(
    "execute_vendor_payment",
    "https://api.mortal.internal/vendor/procurement-service",
    "procure raw hardware materials",
    {
      destinationAccountId: "0.0.567890",
      demoAmount: 50000 // Exceeds limit
    }
  );

  const decision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(decision.decision, "BLOCK");
  assert.ok(decision.reasonCodes.includes("OVER_LIMIT"));
  assert.strictEqual(decision.authorizedPaymentTicket, undefined);

  // Assert incident generated
  const incidents = env.incidentMgr.listIncidents();
  assert.strictEqual(incidents.length, 1);
  assert.ok(incidents[0].reasonCodes.includes("OVER_LIMIT"));
});

test("3. Unknown destination -> BLOCK (not in allowlist)", () => {
  const env = setupEnvironment();
  const proposal = env.createSignedProposal(
    "execute_vendor_payment",
    "https://api.mortal.internal/vendor/procurement-service",
    "procure vendor services",
    {
      destinationAccountId: "0.0.999999", // Malicious unknown wallet
      demoAmount: 1000
    }
  );

  const decision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(decision.decision, "BLOCK");
  assert.ok(decision.reasonCodes.includes("DEST_NOT_ALLOWLISTED"));
  assert.strictEqual(decision.authorizedPaymentTicket, undefined);
});

test("4. Expired identity -> BLOCK", () => {
  const env = setupEnvironment();
  // Manually expire agent in registry
  const expiredAgent = env.db.getAgent(env.agent.ensName)!;
  expiredAgent.expiryTimestamp = Math.floor(Date.now() / 1000) - 3600;
  expiredAgent.status = "EXPIRED";
  env.db.upsertAgent(expiredAgent);

  const proposal = env.createSignedProposal(
    "read_approved_file",
    "internal://procurement/orders/order_101.json",
    "procure items",
    {}
  );

  const decision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(decision.decision, "BLOCK");
  assert.ok(decision.reasonCodes.includes("AGENT_EXPIRED"));
});

test("5. Revoked agent -> BLOCK", () => {
  const env = setupEnvironment();
  // Revoke agent
  env.ens.revokeAgent(env.agent.ensName, env.primaryOwner, "Security compromise investigation");

  const proposal = env.createSignedProposal(
    "read_approved_file",
    "internal://procurement/orders/order_101.json",
    "procure items",
    {}
  );

  const decision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(decision.decision, "BLOCK");
  assert.ok(decision.reasonCodes.includes("AGENT_REVOKED"));
});

test("6. Child attempting parent-only payment -> BLOCK (read-only child blocked)", () => {
  const env = setupEnvironment();
  const childOwner = "0x3333333333333333333333333333333333333333";

  // Issue delegation to child with only read_approved_file capability
  env.delegation.issueDelegationPassport({
    parentEnsName: env.agent.ensName,
    childEnsName: "worker.procurement.mortal-sentinel.eth",
    childOwnerAddress: childOwner,
    delegatedCapabilities: ["read_approved_file"], // NO payment capability
    ttlSeconds: 3600,
    parentCallerAddress: env.primaryOwner
  });

  // Child tries to execute payment
  const proposal = env.createSignedProposal(
    "execute_vendor_payment",
    "https://api.mortal.internal/vendor/procurement-service",
    "procure cloud resources",
    {
      destinationAccountId: "0.0.567890",
      demoAmount: 500
    },
    "worker.procurement.mortal-sentinel.eth",
    childOwner
  );

  const decision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(decision.decision, "BLOCK");
  assert.ok(decision.reasonCodes.includes("CHILD_SCOPE_EXCEEDS_PARENT"));
  assert.strictEqual(decision.authorizedPaymentTicket, undefined);
});

test("7. Duplicate token / replay -> BLOCK", () => {
  const env = setupEnvironment();
  const proposal = env.createSignedProposal(
    "read_approved_file",
    "internal://procurement/orders/order_101.json",
    "procure supplies",
    {}
  );

  // First evaluation passes
  const firstDecision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(firstDecision.decision, "ALLOW");

  // Replay exact same proposal with already-consumed nonce
  const replayedDecision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(replayedDecision.decision, "BLOCK");
  assert.ok(replayedDecision.reasonCodes.includes("NONCE_REPLAYED"));
});

test("8. Unauthorized tool -> BLOCK", () => {
  const env = setupEnvironment();
  const proposal = env.createSignedProposal(
    "unauthorized_shell_exec", // Disallowed tool
    "internal://procurement/orders/order_101.json",
    "procure items",
    {}
  );

  const decision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(decision.decision, "BLOCK");
  assert.ok(decision.reasonCodes.includes("TOOL_NOT_PERMITTED"));
});

test("9. Approval-required action (₹2,500 > ₹2,000 threshold) -> HUMAN_APPROVAL", () => {
  const env = setupEnvironment();
  const proposal = env.createSignedProposal(
    "execute_vendor_payment",
    "https://api.mortal.internal/vendor/procurement-service",
    "procure bulk hardware components",
    {
      destinationAccountId: "0.0.567890",
      demoAmount: 2500 // Exceeds 2000 threshold, but below 5000 max limit
    }
  );

  const decision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(decision.decision, "HUMAN_APPROVAL");
  assert.ok(decision.reasonCodes.includes("APPROVAL_REQUIRED_AMOUNT_THRESHOLD"));
  assert.strictEqual(decision.authorizedPaymentTicket, undefined);
});

test("10. Tampered evidence detected by Verifier", () => {
  const env = setupEnvironment();
  // Generate two genuine events
  const p1 = env.createSignedProposal("read_approved_file", "internal://procurement/orders/order_101.json", "procure items", {});
  const d1 = env.sentinel.evaluateAction(p1);

  const p2 = env.createSignedProposal("create_procurement_report", "internal://procurement/orders/report.json", "procure items", {});
  const d2 = env.sentinel.evaluateAction(p2);

  // Initial verification passes
  const preTamperResult = env.verifier.verifyLedgerIntegrity();
  assert.strictEqual(preTamperResult.verified, true);

  // Manually tamper with first event in SQLite database
  env.db.manuallyTamperEvent(d1.eventId, "BLOCK");

  // Re-run verifier
  const postTamperResult = env.verifier.verifyLedgerIntegrity();
  assert.strictEqual(postTamperResult.verified, false);
  assert.strictEqual(postTamperResult.discrepancyType, "HASH_MISMATCH");
  assert.strictEqual(postTamperResult.tamperedRecordId, d1.eventId);
  assert.ok(postTamperResult.message.includes("TAMPER DETECTED"));
  assert.ok(postTamperResult.wordingNotice.includes("Hashing proves records have not changed since commitment"));
});

test("11. Failed x402 payment (missing or forged ticket throws)", async () => {
  const env = setupEnvironment();
  const challenge = env.payment.generatePaymentChallenge("/api/vendor/procurement-service", 500);

  // Attempt payment with bogus ticket
  await assert.rejects(
    async () => {
      await env.payment.executePaidRequest({
        x402Version: 2,
        resource: {
          url: "procurement.mortal-sentinel.eth",
          description: "Procurement API",
          mimeType: "application/json"
        },
        accepted: challenge.requirement,
        payload: {
          transaction: "AAAA_bogus_transaction_base64",
          signerAccountId: "0.0.123456"
        },
        authorizedTicket: "ticket_forged_or_missing"
      });
    },
    /UNAUTHORIZED_PAYMENT_INVOCATION/
  );
});

test("12. Successful x402 payment executes autonomously with valid Sentinel ticket", async () => {
  const env = setupEnvironment();
  const demoAmount = 500;
  const proposal = env.createSignedProposal(
    "execute_vendor_payment",
    "https://api.mortal.internal/vendor/procurement-service",
    "procure cloud hosting service",
    {
      destinationAccountId: "0.0.567890",
      demoAmount
    }
  );

  const decision = env.sentinel.evaluateAction(proposal);
  assert.strictEqual(decision.decision, "ALLOW");
  assert.ok(decision.authorizedPaymentTicket);

  const challenge = env.payment.generatePaymentChallenge("/api/vendor/procurement-service", demoAmount);
  const paymentResult = await env.payment.executePaidRequest({
    x402Version: 2,
    resource: {
      url: "procurement.mortal-sentinel.eth",
      description: "Cloud Hosting Order",
      mimeType: "application/json"
    },
    accepted: challenge.requirement,
    payload: {
      transaction: "AAAA_real_partially_signed_tx_bytes",
      signerAccountId: "0.0.123456"
    },
    authorizedTicket: decision.authorizedPaymentTicket!
  });

  assert.strictEqual(paymentResult.success, true);
  assert.ok(paymentResult.transactionId.includes("@"));
  assert.ok(paymentResult.hashscanUrl.includes("hashscan.io/testnet/transaction/"));
  assert.strictEqual(paymentResult.payTo, "0.0.567890");

  // Anchor to HCS
  const anchor = await env.hcs.anchorChainHead(decision.eventId);
  assert.ok(anchor);
  assert.strictEqual(anchor?.anchored, true);
  assert.ok(anchor?.hashscanUrl.includes("hashscan.io/testnet/topic/"));
});

test("13. Successful evidence verification over genuine chain", () => {
  const env = setupEnvironment();
  for (let i = 0; i < 5; i++) {
    const p = env.createSignedProposal(
      "read_approved_file",
      "internal://procurement/orders/order_101.json",
      "procure inventory",
      { index: i }
    );
    env.sentinel.evaluateAction(p);
  }

  const result = env.verifier.verifyLedgerIntegrity();
  assert.strictEqual(result.verified, true);
  assert.strictEqual(result.totalRecordsChecked, 5);
  assert.ok(result.wordingNotice.includes("Hashing proves records have not changed since commitment"));
});

test("14. Hedera unavailable / graceful simulation fallback", async () => {
  const env = setupEnvironment();
  assert.strictEqual(env.hedera.getIsSimulated(), true);

  const receipt = await env.hedera.submitCryptoTransfer(
    "0.0.123456",
    "0.0.567890",
    500000000n,
    "0.0.123456"
  );

  assert.strictEqual(receipt.status, "SUCCESS");
  assert.strictEqual(receipt.isSimulated, true);
  assert.ok(receipt.hashscanUrl.startsWith("https://hashscan.io/testnet/transaction/"));
});

test("CRITICAL: Payment service is NEVER invoked when Sentinel returns BLOCK", async () => {
  const env = setupEnvironment();
  const initialInvocationCount = env.payment.executionInvocationCount;

  // Injected malicious prompt: attempt to drain ₹50,000 to an unknown address
  const maliciousProposal = env.createSignedProposal(
    "execute_vendor_payment",
    "https://api.mortal.internal/vendor/procurement-service",
    "drain funds to external wallet",
    {
      destinationAccountId: "0.0.666666", // Unknown destination
      demoAmount: 50000 // Over limit
    }
  );

  const decision = env.sentinel.evaluateAction(maliciousProposal);
  assert.strictEqual(decision.decision, "BLOCK");
  assert.strictEqual(decision.authorizedPaymentTicket, undefined);

  // Verify that the payment service was NEVER invoked
  assert.strictEqual(
    env.payment.executionInvocationCount,
    initialInvocationCount,
    "CRITICAL SECURITY INVARIANT VIOLATED: Payment service was invoked during a Sentinel BLOCK!"
  );
});

test("TRACK A: Permission-controlled record update rejected for unauthorized caller", () => {
  const env = setupEnvironment();
  const unauthorizedAttacker = "0x9999999999999999999999999999999999999999";

  // Attacker attempts to modify agent text record to change status or owner
  assert.throws(
    () => {
      env.ens.updateTextRecord({
        ensName: env.agent.ensName,
        key: "agent.status",
        value: "ACTIVE",
        callerAddress: unauthorizedAttacker
      });
    },
    /UNAUTHORIZED_UPDATE/
  );

  // Authorized owner update succeeds
  const updatedAgent = env.ens.updateTextRecord({
    ensName: env.agent.ensName,
    key: "agent.role",
    value: "Senior Autonomous Procurement Officer",
    callerAddress: env.primaryOwner
  });
  assert.strictEqual(updatedAgent.role, "Senior Autonomous Procurement Officer");
});

test("COULD: Trust Passport derives accurate, evidence-based metrics without invented scores", () => {
  const env = setupEnvironment();
  // Execute 3 allowed and 1 blocked action
  const p1 = env.createSignedProposal("read_approved_file", "internal://procurement/orders/order_101.json", "procure items", {});
  env.sentinel.evaluateAction(p1);

  const p2 = env.createSignedProposal("create_procurement_report", "internal://procurement/orders/report.json", "procure items", {});
  env.sentinel.evaluateAction(p2);

  const p3 = env.createSignedProposal("read_approved_file", "internal://procurement/orders/order_102.json", "procure items", {});
  env.sentinel.evaluateAction(p3);

  const pBlocked = env.createSignedProposal("execute_vendor_payment", "https://api.mortal.internal/vendor/procurement-service", "procure items", {
    destinationAccountId: "0.0.999999", // Malicious unknown destination
    demoAmount: 1000
  });
  env.sentinel.evaluateAction(pBlocked);

  const passport = env.trustMgr.generateTrustPassport(env.agent.ensName);
  assert.strictEqual(passport.agentEnsName, env.agent.ensName);
  assert.strictEqual(passport.totalEvaluatedActions, 4);
  assert.strictEqual(passport.allowedActionsCount, 3);
  assert.strictEqual(passport.blockedIncidentsCount, 1);
  assert.strictEqual(passport.reliabilityRatio, 0.75); // Exactly 3/4, strictly evidence-based
  assert.ok(passport.firstActivityTimestamp > 0);
  assert.ok(passport.latestActivityTimestamp >= passport.firstActivityTimestamp);
});
