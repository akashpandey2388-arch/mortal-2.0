/**
 * MORTAL 2.0 — Sentinel Policy Configuration
 * Authoritative parameters for deterministic authorization gating.
 */

import { CURRENCY_CONFIG } from "./currency.ts";

export interface PolicyConfig {
  policyVersion: string;
  allowedTools: string[];
  allowedResources: string[];
  approvedMerchants: {
    id: string;
    name: string;
    endpoint: string;
    hederaAccountId: string;
    description: string;
  }[];
  paymentLimits: {
    maxPerPaymentDemo: number;
    periodSpendingLimitDemo: number; // e.g. per 24 hours
    periodDurationSeconds: number;
    maxFrequencyPerHour: number;
    humanApprovalThresholdDemo: number;
  };
  delegationRules: {
    maxDelegationDepth: number;
    allowPaymentDelegation: boolean;
  };
}

export const DEFAULT_POLICY: PolicyConfig = {
  policyVersion: "2026.11.v2.0-sentinel",
  allowedTools: [
    "read_approved_file",
    "create_procurement_report",
    "execute_vendor_payment",
    "query_inventory",
    "verify_goods_receipt"
  ],
  allowedResources: [
    "internal://procurement/orders/*",
    "internal://inventory/catalog",
    "https://api.mortal.internal/vendor/*"
  ],
  approvedMerchants: [
    {
      id: "vendor-a",
      name: "Vendor A (Official Procurement Partner)",
      endpoint: "/api/vendor/procurement-service",
      hederaAccountId: "0.0.567890", // Testnet account for Vendor A
      description: "Authorized cloud compute and procurement API service"
    }
  ],
  paymentLimits: {
    maxPerPaymentDemo: CURRENCY_CONFIG.maxPaymentDemoAmount, // ₹5,000 max
    periodSpendingLimitDemo: 20000, // ₹20,000 per 24h
    periodDurationSeconds: 86400,
    maxFrequencyPerHour: 10,
    humanApprovalThresholdDemo: CURRENCY_CONFIG.approvalThresholdDemoAmount // ₹2,000 triggers HUMAN_APPROVAL
  },
  delegationRules: {
    maxDelegationDepth: 2,
    allowPaymentDelegation: false // Child agents cannot execute payments (parent-only capability)
  }
};
