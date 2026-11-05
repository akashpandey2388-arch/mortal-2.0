/**
 * MORTAL 2.0 — Currency & Exchange Rate Configuration
 * 
 * IMPORTANT LABELLED CONSTANT:
 * Section 7 Specification: "Amounts: ₹5,000 max payment, mapped to a testnet token amount 
 * through ONE documented, labelled constant (e.g. in /config/currency.ts). Do not call it real INR."
 * 
 * This file establishes the single authoritative mapping from benchmark units (labelled Demo INR / ₹)
 * to Hedera Testnet token units (HBAR / tinybars).
 * Note: These are simulated testnet exchange benchmarks and NOT real fiat currency.
 */

export interface CurrencyConfig {
  /** Labelled demonstration currency symbol */
  demoCurrencySymbol: string;
  /** Labelled demonstration currency code */
  demoCurrencyCode: string;
  /** Maximum payment limit permitted in demonstration units (₹5,000) */
  maxPaymentDemoAmount: number;
  /** Exchange rate: 1 Demo INR unit = X tinybars (1 HBAR = 100,000,000 tinybars) */
  tinybarsPerDemoUnit: bigint;
  /** Human approval threshold in demonstration units (e.g. ₹2,000 triggers human sign-off) */
  approvalThresholdDemoAmount: number;
}

/**
 * Benchmark exchange rate:
 * 1 Demo INR (₹) = 1,000,000 tinybars (0.01 HBAR)
 * Maximum ₹5,000 payment = 5,000 * 1,000,000 = 5,000,000,000 tinybars (50 HBAR)
 * Approval threshold ₹2,000 = 2,000,000,000 tinybars (20 HBAR)
 */
export const CURRENCY_CONFIG: CurrencyConfig = {
  demoCurrencySymbol: "₹",
  demoCurrencyCode: "DEMO_INR",
  maxPaymentDemoAmount: 5000,
  tinybarsPerDemoUnit: 1000000n, // 0.01 HBAR per demo unit
  approvalThresholdDemoAmount: 2000,
};

/**
 * Converts demonstration INR units to Hedera testnet tinybars.
 * @param demoAmount Amount in labelled demo currency
 * @returns Amount in tinybars (bigint)
 */
export function demoUnitsToTinybars(demoAmount: number): bigint {
  if (demoAmount < 0) {
    throw new Error("Currency amount cannot be negative");
  }
  return BigInt(Math.floor(demoAmount)) * CURRENCY_CONFIG.tinybarsPerDemoUnit;
}

/**
 * Converts Hedera testnet tinybars to demonstration INR units.
 * @param tinybars Amount in tinybars
 * @returns Amount in demo currency units
 */
export function tinybarsToDemoUnits(tinybars: bigint): number {
  return Number(tinybars / CURRENCY_CONFIG.tinybarsPerDemoUnit);
}

/**
 * Formats demonstration currency display.
 * @param demoAmount Amount in labelled demo units
 */
export function formatDemoCurrency(demoAmount: number): string {
  return `${CURRENCY_CONFIG.demoCurrencySymbol}${demoAmount.toLocaleString("en-IN")} (${CURRENCY_CONFIG.demoCurrencyCode})`;
}
