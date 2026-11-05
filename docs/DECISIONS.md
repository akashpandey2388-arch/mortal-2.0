# MORTAL 2.0 — Architectural Decisions Log

## DEC-001: Project Structure and Organization
- **Date**: 2026-11-06
- **Context**: MORTAL 2.0 requires a fullstack accountability infrastructure comprising an autonomous AI agent layer, Sentinel deterministic authorization gateway, Hedera x402 payment engine, Black Box evidence hash chain with Hedera Consensus Service (HCS) anchoring, and an operator dashboard.
- **Decision**: Organize the project with a high-integrity TypeScript architecture:
  - `/docs`: All audit, feasibility, progress, attribution, architecture, and demo documentation.
  - `/config`: Centralized system parameters, including `/config/currency.ts` (mapping ₹5,000 max payment to testnet token/tinybars via single documented constant), `/config/policy.ts`, `/config/contracts.ts`.
  - `/src/lib/sentinel`: The 10-step deterministic authorization engine (`SentinelGateway.ts`, `PolicyEngine.ts`, `IntentValidator.ts`, `RiskEngine.ts`, `CapabilityManager.ts`).
  - `/src/lib/blackbox`: Cryptographic evidence ledger (`EventRecorder.ts`, `HashChain.ts`, `EvidenceVerifier.ts`, `IncidentManager.ts`).
  - `/src/lib/identity`: ENSv2 and ERC-8004 identity management (`EnsIdentityManager.ts`, `DelegationManager.ts`).
  - `/src/lib/hedera`: Hedera x402 payment and HCS anchoring client (`HederaClient.ts`, `HcsAnchoringService.ts`, `X402PaymentService.ts`).
  - `/src/lib/db`: Persistent SQLite store.
  - `/src/server`: Express/Next API server endpoints.
  - `/src/dashboard` or `/src/app`: Modern dark navy/black operator dashboard.
- **Status**: Accepted.

## DEC-002: Database Engine Selection
- **Date**: 2026-11-06
- **Context**: Section 8 specifies: "Prefer the simplest reliable DB (MongoDB if the repo already uses it, otherwise SQLite is acceptable; record the choice)."
- **Decision**: Use Node.js 24 built-in `node:sqlite` (`DatabaseSync`).
- **Rationale**:
  1. The environment runs Node.js v24.14.1, which natively embeds SQLite with zero external C++ dependencies, eliminating gyp compilation errors common with `better-sqlite3` on Windows.
  2. ACID compliant, synchronous, supports disk persistence and in-memory test suites.
  3. No external daemon (like MongoDB) required, guaranteeing immediate local execution across any developer or judge environment.
- **Status**: Accepted.

## DEC-003: ENS Domain Strategy & Sepolia Setup
- **Date**: 2026-11-06
- **Context**: We must use an ENS name we own and control for registering the procurement agent subname (`procurement.<name>.eth`).
- **Decision**: Default to `mortal-sentinel.eth` as parent domain with `procurement.mortal-sentinel.eth` as the agent subname.
- **Rationale**: We implement direct cryptographic ownership checks using Sepolia ENS contracts (NameWrapper `0xab50971078225D365994dc1Edcb9b7FD72Bb4862` and PublicResolver `0x6925affDa98274FE0376250187CCC4aC62866dCd`). For environments lacking live Sepolia gas or active RPC connection, an authenticated local ENS provider mirror enforces identical interface, EIP-712 signatures, fuse rules, and rejection on unauthorized text record updates with clear "SIMULATED" badge indication when live RPC is offline.
- **Status**: Accepted.

## DEC-004: Hedera x402 Payment & Facilitator Architecture
- **Date**: 2026-11-06
- **Context**: Hedera x402 requires a protected endpoint, facilitator co-signing fee-payer model, client partial signature, and on-chain settlement.
- **Decision**:
  1. Implement an x402-compliant endpoint `/api/vendor/procurement-service` enforcing standard HTTP 402 `PaymentRequirements`.
  2. Implement a built-in Hedera Facilitator service conforming to `@x402/hedera` specification that receives partially signed `TransferTransaction` payloads, co-signs as fee-payer, and executes to Hedera testnet via `@hashgraph/sdk`.
  3. Single-use gateway authorization token: The payment service cannot be invoked directly without an ephemeral, single-use ticket minted exclusively by SentinelGateway after passing all 10 policy checks.
  4. Currency constant: Enforce ₹5,000 maximum limit mapped to 50 HBAR ($5 \times 10^9$ tinybars) in `/config/currency.ts`.
- **Status**: Accepted.

## DEC-005: Black Box & Hash Chain Invariants
- **Date**: 2026-11-06
- **Context**: Invariant: Every sensitive action and Sentinel decision (ALLOW, BLOCK, HUMAN_APPROVAL) must be immutably recorded in a SHA-256 hash chain with periodic HCS anchoring.
- **Decision**:
  - Hash computation: Canonical JSON serialization (deterministic sorted keys) + previous record hash:
    $$H_n = \text{SHA-256}(H_{n-1} \parallel \text{CanonicalJSON}(R_n))$$
  - Wording rule enforced in all UI and verifier reports: Hashing proves records have not been altered since commitment; it does not prove the original source data was truthful.
  - HCS commitment: Hash chain head and Merkle root submitted to Hedera Consensus Service topic; returns Topic ID, Sequence Number, and Consensus Timestamp.
- **Status**: Accepted.
