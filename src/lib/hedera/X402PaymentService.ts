/**
 * MORTAL 2.0 — Hedera x402 Payment Service & Facilitator
 * Implements the HTTP 402 Payment Required standard on Hedera testnet.
 * 
 * CORE INVARIANT:
 * The payment adapter is UNREACHABLE without a valid, single-use, short-lived authorization ticket
 * issued exclusively by SentinelGateway after passing all 10 policy checks.
 * A test explicitly proves the payment service is NOT invoked when Sentinel blocks.
 */

import type {
  X402PaymentRequirement,
  X402PaymentPayload,
  X402PaymentResult
} from "../../types/index.ts";
import { CONTRACTS } from "../../../config/contracts.ts";
import { CURRENCY_CONFIG, demoUnitsToTinybars } from "../../../config/currency.ts";
import { DatabaseService } from "../db/database.ts";
import { HederaClient } from "./HederaClient.ts";

export class X402PaymentService {
  private db: DatabaseService;
  private hederaClient: HederaClient;
  private vendorAccountId: string;
  private facilitatorAccountId: string;

  // Audit counter to prove whether payment service was ever touched
  public executionInvocationCount: number = 0;

  constructor(
    db: DatabaseService,
    hederaClient: HederaClient,
    vendorAccountId: string = CONTRACTS.hedera.defaultVendorAccountId,
    facilitatorAccountId: string = CONTRACTS.hedera.defaultFacilitatorAccountId
  ) {
    this.db = db;
    this.hederaClient = hederaClient;
    this.vendorAccountId = vendorAccountId;
    this.facilitatorAccountId = facilitatorAccountId;
  }

  /**
   * Generates the HTTP 402 Payment Required challenge for a requested service.
   * Conforms to the x402 exact scheme for Hedera.
   */
  public generatePaymentChallenge(
    resourcePath: string,
    demoAmount: number = 100
  ): {
    status: 402;
    headers: Record<string, string>;
    requirement: X402PaymentRequirement;
  } {
    const tinybars = demoUnitsToTinybars(demoAmount).toString();

    const requirement: X402PaymentRequirement = {
      scheme: "exact",
      network: CONTRACTS.hedera.caip2,
      amount: tinybars,
      asset: "0.0.0", // Native HBAR
      payTo: this.vendorAccountId,
      maxTimeoutSeconds: 180,
      extra: {
        feePayer: this.facilitatorAccountId,
        assetTransferMethods: ["cryptoTransfer"],
        demoAmount,
        demoCurrency: CURRENCY_CONFIG.demoCurrencyCode
      }
    };

    return {
      status: 402,
      headers: {
        "PAYMENT-REQUIRED": JSON.stringify(requirement),
        "Content-Type": "application/json"
      },
      requirement
    };
  }

  /**
   * Executes autonomous x402 payment co-signed by the Facilitator.
   * STRICT GATING:
   * Rejects immediately if authorizedTicket is missing, expired, mismatched, or already used.
   */
  public async executePaidRequest(paymentPayload: X402PaymentPayload): Promise<X402PaymentResult> {
    this.executionInvocationCount++;

    if (!paymentPayload.authorizedTicket) {
      throw new Error(
        "UNAUTHORIZED_PAYMENT_INVOCATION: Missing Sentinel gateway authorization ticket. Payment execution blocked."
      );
    }

    const { accepted, payload, authorizedTicket } = paymentPayload;
    const payerAccountId = payload.signerAccountId;
    const destAccountId = accepted.payTo;
    const amountTinybars = accepted.amount;

    // Atomically validate and consume the single-use ticket in the database
    const ticketConsumed = this.db.consumePaymentTicket(
      authorizedTicket,
      paymentPayload.resource.url.split("/")[0] || "procurement.mortal-sentinel.eth",
      amountTinybars,
      destAccountId
    );

    // If ticket was invalid or already consumed
    if (!ticketConsumed) {
      throw new Error(
        `UNAUTHORIZED_PAYMENT_INVOCATION: Invalid, expired, or replayed payment ticket "${authorizedTicket}". Payment blocked by gateway barrier.`
      );
    }

    // Submit the transfer through the Hedera testnet client (facilitator sponsors gas/fees)
    const receipt = await this.hederaClient.submitCryptoTransfer(
      payerAccountId,
      destAccountId,
      BigInt(amountTinybars),
      this.facilitatorAccountId
    );

    return {
      success: true,
      transactionId: receipt.transactionId,
      consensusTimestamp: receipt.consensusTimestamp,
      hashscanUrl: receipt.hashscanUrl,
      amountTinybars,
      payTo: destAccountId,
      payerAccountId,
      feePayerAccountId: this.facilitatorAccountId,
      isSimulated: receipt.isSimulated
    };
  }
}
