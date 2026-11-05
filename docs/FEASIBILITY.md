# MORTAL 2.0 — Feasibility Study & Architecture Assessment (Stage 0)

**Date**: 2026-11-06  
**Status**: COMPLETE (Approved for Stage 1 & 2 Execution)  

---

## 1. ENSv2 & Agent Identity Verification

### Current Contracts & Network Deployment
- **Target Network**: Ethereum Sepolia Testnet.
- **Official Documentation**: [ENS Documentation](https://docs.ens.domains) & [ENS Contracts](https://github.com/ensdomains/ens-contracts)
- **Active Sepolia Deployed Contracts**:
  - **NameWrapper**: `0xab50971078225D365994dc1Edcb9b7FD72Bb4862` (ERC-1155 subname wrapper with fuses, expiry, and permission controls)
  - **PublicResolver**: `0x6925affDa98274FE0376250187CCC4aC62866dCd` (Multicall, text records, addr resolution)
  - **ENS Registry**: `0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e`
  - **Universal Resolver**: `0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe`

### Parent Name & Subname Strategy
- **Parent Name**: `mortal-sentinel.eth` (controlled by deployment operator on Sepolia).
- **Agent Identity**: `procurement.mortal-sentinel.eth`.
- **Subname Registration Flow**:
  1. Parent name owner calls `NameWrapper.setSubnodeRecord(...)` or `setSubnodeOwner(...)`.
  2. Subname fuses set (e.g. `CANNOT_UNWRAP`, `PARENT_CANNOT_CONTROL`) with defined expiry timestamp.
  3. Resolver text records set via `PublicResolver.setText(...)`:
     - `agent.id`: Unique cryptographic identifier
     - `agent.role`: `Autonomous Procurement Agent`
     - `agent.status`: `ACTIVE` (or `REVOKED`)
     - `agent.expiry`: ISO timestamp or Unix epoch
     - `agent.owner`: Authorized controller EVM address
- **Unauthorized Update Rejection**:
  Only the subname owner or parent admin (if fuse permits) can call `setText` or modify records. Any attempt by an unauthorized third party reverts on-chain or fails signature validation.
- **Feasibility Verdict**: **GO** (Sepolia contracts active; local mirror with identical ABI fallback if Sepolia RPC is offline).

---

## 2. Hedera x402 Autonomous Payments

### Protocol & Official Documentation
- **Official Hedera Documentation**: [Hedera x402 Solutions](https://docs.hedera.com/solutions/ai/x402)
- **Protocol Specification**: [x402-foundation/x402 exact scheme for Hedera](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact_hedera.md)
- **NPM Integration Packages**: `@x402/hedera`, `@hashgraph/sdk` (or `@hiero-ledger/sdk`).

### Facilitator & Fee-Payer Mechanism
- In the Hedera exact payment scheme, the resource server requires a specific payment amount (`PaymentRequirements`).
- The client constructs and partial-signs a `TransferTransaction` for native HBAR (`asset: "0.0.0"`, specified in tinybars) or HTS token.
- A **Facilitator** acts as the designated fee payer (`extra.feePayer`):
  1. Resource server returns HTTP `402 Payment Required` with `PaymentRequirements`.
  2. Client authorizes and signs the transaction body.
  3. Client resubmits request with `X-Payment` header containing the Base64 transaction payload.
  4. Facilitator validates payment criteria, signs the transaction as fee payer, and broadcasts to Hedera testnet.
  5. Response returns `PAYMENT-RESPONSE` with on-chain transaction ID (linkable on HashScan: `https://hashscan.io/testnet/transaction/<txId>`).

### Security Gateway Gating
- The payment adapter cannot be invoked directly by any agent or tool. It strictly requires a single-use authorization ticket minted by SentinelGateway after passing all 10 policy checks.
- **Feasibility Verdict**: **GO**.

---

## 3. Hedera Consensus Service (HCS)

### Topic Creation & Message Submission
- **SDK**: `@hashgraph/sdk`
- **Official Documentation**: [Hedera Consensus Service Docs](https://docs.hedera.com/hedera/sdks-and-apis/sdks/consensus-service)
- **Topic Creation**:
  ```ts
  const tx = await new TopicCreateTransaction()
    .setTopicMemo("MORTAL-2.0-Audit-Ledger")
    .execute(client);
  const receipt = await tx.getReceipt(client);
  const topicId = receipt.topicId.toString();
  ```
- **Message Submission**:
  ```ts
  const tx = await new TopicMessageSubmitTransaction()
    .setTopicId(topicId)
    .setMessage(JSON.stringify(anchorCommitment))
    .execute(client);
  const receipt = await tx.getReceipt(client);
  // Captures receipt.topicSequenceNumber and consensusTimestamp
  ```
- **Auditing**: Every topic submission is verifiable on HashScan: `https://hashscan.io/testnet/topic/<topicId>`.
- **Feasibility Verdict**: **GO**.

---

## 4. open-agents-toolkit Evaluation

Reference repository: [cladjules/open-agents-toolkit](https://github.com/cladjules/open-agents-toolkit)

| Component | Assessment & Strategy | Compatibility & Implementation Plan |
|---|---|---|
| **ENS Agent Subname & Metadata Scheme** | **Reuse & Extend** | Adopt the ENS text-record convention for agent profiles (`agent.role`, `agent.expiry`, `agent.revoked`). Implement on Sepolia NameWrapper/PublicResolver. |
| **ERC-8004 Trust Passport Model** | **Modify** | Adopt the ERC-8004 concept of verifiable validation/reputation metrics. In MORTAL, all metrics are strictly derived from verifiable Black Box hash chain counts and HCS timestamps — zero invented or hallucinated scores. |
| **Sentinel Gateway & Policy Engine** | **Build from Scratch** | Not present in OAT. MORTAL requires an independent 10-step deterministic Sentinel pipeline (signature -> ENS -> lifecycle -> tools -> intent -> delegation -> payment -> risk -> approval -> allow) with single-use payment authorizations. |
| **Hedera x402 & HCS Anchoring** | **Build from Scratch** | OAT focused on EVM/0G storage. Hedera x402 HTTP micro-payments and HCS hash chain anchoring are unique to MORTAL. |
| **Compatibility Issues** | **Mitigated** | OAT's reliance on custom TEE nodes and 0G storage is replaced with standard Hedera Testnet and Sepolia contracts, ensuring zero external vendor lock-in and 100% deterministic local verification. |

---

## 5. Track Feasibility Summary & Fallback Plan

| Track / Capability | Feasibility Status | Primary Execution | Fallback Plan (Dev Adapter) |
|---|---|---|---|
| **Track A: ENSv2 Identity** | **GO** | Ethereum Sepolia testnet contracts (`0xab50...`, `0x6925...`). | Cryptographic local resolver enforcing identical ABI, EIP-712 signatures, and permission checks with clear `[SIMULATED]` UI badge when RPC is offline. |
| **Track B: Hedera x402 Payments** | **GO** | Live Hedera Testnet via `@hashgraph/sdk` + x402 Facilitator. | Standalone local facilitator co-signing against Hedera testnet; if Hedera network is unreachable, DEV payment adapter with `[SIMULATED]` badge and full mock transaction lifecycle. |
| **Hedera HCS Anchoring** | **GO** | Live HCS topic creation & message submit on Hedera Testnet. | Queued local anchor with `[SIMULATED]` flag if network unavailable; seamless sync upon reconnection. |
| **Sentinel Policy Engine** | **GO** | In-process deterministic TypeScript engine (100% testable). | Native deterministic execution. |
| **Black Box Hash Chain** | **GO** | SHA-256 canonical JSON hash chain + tamper verification. | Native deterministic execution. |
| **Operator Dashboard** | **GO** | Dark navy/black Next.js / React UI. | Direct connection to local SQLite / REST API. |

**Proceeding immediately to Stage 1 Implementation Plan and Stage 2 Foundation.**
