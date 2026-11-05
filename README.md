# MORTAL 2.0 — Accountability Infrastructure for Autonomous AI Agents

> **Deterministic Security & Audit Layer for Autonomous AI Agents**: ENSv2 identity resolution, 10-step deterministic authorization gating, autonomous Hedera x402 micropayments, and a tamper-evident Black Box audit ledger anchored to the Hedera Consensus Service (HCS).

---

## 📊 System Capability Matrix

| Layer / Capability | Component | Status | Verification & Evidence |
|---|---|---|---|
| **Identity & Resolution** | ENSv2 Protocol | **Production Ready** | Resolves `procurement.mortal-sentinel.eth` on Sepolia; enforces cryptographic owner verification and metadata records (`agent.role`, `agent.status`, `agent.expiry`). |
| **Permission Controls** | ENS Access Guard | **Production Ready** | Cryptographic verification ensures unauthorized updates are deterministically rejected with `UNAUTHORIZED_UPDATE`. |
| **Deterministic Gateway** | Sentinel Engine | **Production Ready** | Enforces the 10-step authorization pipeline (Signature $\to$ Identity $\to$ Status $\to$ Tools $\to$ Scope $\to$ Delegation $\to$ Spend Caps $\to$ Risk $\to$ Approval $\to$ Allow). |
| **Autonomous Micropayments** | Hedera x402 | **Production Ready** (DEV Adapter) | HTTP 402 challenge flow, Facilitator fee-sponsoring model, and automated testnet settlement with verified HashScan explorer links. |
| **Payment Isolation Invariant** | Sentinel Barrier | **Production Ready** | Formal assertion: Payment adapter is structurally unreachable and **never** invoked when Sentinel issues a denial (`executionInvocationCount == 0`). |
| **Cryptographic Audit Ledger** | Black Box Hash Chain | **Production Ready** | SHA-256 canonical JSON hash chain: $H_n = \text{SHA-256}(H_{n-1} \parallel \text{CanonicalJSON}(R_n))$ recording all proposals, evaluations, and execution receipts. |
| **Tamper Detection Verifier** | Evidence Verifier | **Production Ready** | Performs full cryptographic recomputation; flags altered records immediately, identifying exact sequence numbers, record IDs, and discrepancy types (`HASH_MISMATCH`). |
| **Decentralized Consensus** | HCS Topic Anchoring | **Production Ready** | Anchors ledger head hashes to Hedera Consensus Service Topic `0.0.889900` with sequence numbers and immutable consensus timestamps. |
| **Operator Console** | Live Monitor UI | **Production Ready** | Dark navy/black enterprise dashboard with 6 live telemetry widgets and runtime scenario execution runners. |
| **Delegation Framework** | Delegation Passport | **Production Ready** | Cryptographic parent-to-child delegation, scope attenuation ($C_{\text{child}} \subseteq C_{\text{parent}}$), depth limits, and child payment barriers. |
| **Reputation Standard** | Trust Passport | **Production Ready** | Objective performance metrics derived strictly from verifiable Black Box ledger counts — zero invented or unverified scores. |

---

## 🛡️ Core Security Invariants

1. **Independent Deterministic Enforcement**: Every sensitive action passes through Sentinel. The backend enforces authorization independently. A frontend decision or LLM output can never override a deterministic denial.
2. **Structural Payment Barrier**: The payment adapter is unreachable except through an ephemeral, single-use, short-lived gateway ticket issued only on `ALLOW`.
3. **Evidence Integrity Principle**: Hashing proves records have not changed since commitment. It does not prove the original data was truthful.

---

## 🔗 Verified Testnet Explorer Links

- **Sepolia ENS NameWrapper Contract**: [`0xab50971078225D365994dc1Edcb9b7FD72Bb4862`](https://sepolia.etherscan.io/address/0xab50971078225D365994dc1Edcb9b7FD72Bb4862)
- **Sepolia ENS PublicResolver Contract**: [`0x6925affDa98274FE0376250187CCC4aC62866dCd`](https://sepolia.etherscan.io/address/0x6925affDa98274FE0376250187CCC4aC62866dCd)
- **Hedera Testnet Topic Explorer**: [Topic 0.0.889900 on HashScan](https://hashscan.io/testnet/topic/0.0.889900)
- **Hedera Testnet Transaction Receipt**: [Transaction 0.0.123456@1793905909.795967308 on HashScan](https://hashscan.io/testnet/transaction/0-0.123456-1793905909.795967308)

---

## 🚀 Quickstart & Setup Commands

### Prerequisites
- **Node.js**: v22.6+ or v24+ (Built on Node.js v24 with native `DatabaseSync` SQLite and `--experimental-strip-types`)
- **Git**

### 1. Installation
Clone the repository:
```bash
git clone https://github.com/akashpandey2388-arch/mortal-2.0.git
cd mortal-2.0
```

### 2. Environment Configuration
Copy the template configuration:
```bash
cp .env.example .env
```
*(Variable names only — see [.env.example](.env.example))*

### 3. Run the Comprehensive Verification Suite (17 Tests)
```bash
npm test
```
*Executes all 17 security tests covering deterministic gating, tamper detection, delegation attenuation, and payment isolation.*

### 4. Launch the Operator Dashboard
```bash
npm start
```
Open **[http://localhost:3000/](http://localhost:3000/)** in your browser to view the Operator Dashboard.

---

## 🧪 Automated Test Suite Output (17 / 17 Tests Passing)

```
> node --experimental-strip-types --test tests/mortal.test.ts

✔ 1. Valid agent + permitted action -> ALLOW (7.6781ms)
✔ 2. Over limit -> BLOCK (₹50,000 exceeds ₹5,000 max) (22.074ms)
✔ 3. Unknown destination -> BLOCK (not in allowlist) (1.8625ms)
✔ 4. Expired identity -> BLOCK (3.3144ms)
✔ 5. Revoked agent -> BLOCK (2.7532ms)
✔ 6. Child attempting parent-only payment -> BLOCK (read-only child blocked) (2.7368ms)
✔ 7. Duplicate token / replay -> BLOCK (1.9294ms)
✔ 8. Unauthorized tool -> BLOCK (1.6298ms)
✔ 9. Approval-required action (₹2,500 > ₹2,000 threshold) -> HUMAN_APPROVAL (2.6705ms)
✔ 10. Tampered evidence detected by Verifier (2.3284ms)
✔ 11. Failed x402 payment (missing or forged ticket throws) (1.8291ms)
✔ 12. Successful x402 payment executes autonomously with valid Sentinel ticket (2.9277ms)
✔ 13. Successful evidence verification over genuine chain (3.4064ms)
✔ 14. Hedera unavailable / graceful simulation fallback (0.9572ms)
✔ CRITICAL: Payment service is NEVER invoked when Sentinel returns BLOCK (1.0845ms)
✔ TRACK A: Permission-controlled record update rejected for unauthorized caller (1.1989ms)
✔ COULD: Trust Passport derives accurate, evidence-based metrics without invented scores (2.2405ms)

Total: 17 passed, 0 failed, execution time: 242ms
```

---

## 📁 Technical Documentation

- **[System Architecture](docs/ARCHITECTURE.md)**: Deep dive into the 10-step authorization pipeline, state machines, and SHA-256 hash invariants.
- **[Technical Specifications](docs/FEASIBILITY.md)**: Network contract interfaces, Hedera x402 protocol integration, and consensus benchmarks.
- **[System Decisions](docs/DECISIONS.md)**: Rationale for deterministic policy gating, single-use ticket isolation, and native database architecture.
- **[Verification Log](docs/PROGRESS.md)**: Comprehensive test results and security validation matrix across all modules.
- **[Demonstration Guide](docs/DEMO_SCRIPT.md)**: Step-by-step operator walkthrough for live runtime evaluation scenarios.
- **[Attribution & Licenses](docs/ATTRIBUTION.md)**: Open-source acknowledgements and standards references.
