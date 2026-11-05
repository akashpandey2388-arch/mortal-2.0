# MORTAL 2.0 — 4-Minute Judge Demo Script

**Total Duration**: 4 minutes  
**Presenter Tone**: Concise, technical, authoritative senior engineer.  
**Prerequisites**: Application running locally (`npm start`), dashboard open at `http://localhost:3000/`.

---

### [00:00 - 00:45] Introduction & The Problem
> *"Judges, autonomous AI agents are rapidly being granted access to sensitive resources: enterprise wallets, APIs, and file systems. When an agent hallucinates or is prompted by an adversary with prompt injection, who is accountable?*  
> *Existing architectures either completely trust the agent or rely on fragile prompt filters. **MORTAL 2.0** solves this by establishing a deterministic cryptographic accountability layer between autonomous agents and sensitive actions."*

**Action**: Point to the top header on the Dashboard.
- Show **ENS Agent Identity**: `procurement.mortal-sentinel.eth` registered under Sepolia ENSv2 contracts.
- Show **Hedera Network**: Connected to Hedera Testnet for x402 micropayments and HCS consensus anchoring.
- Show **Currency Benchmark**: ₹5,000 maximum spending limit mapped to 50 HBAR via a single documented constant in `/config/currency.ts`.

---

### [00:45 - 01:30] Scenario 1 — Authorized Autonomous Procurement
> *"First, let's observe an authorized autonomous workflow. Our procurement agent requests ₹500 in cloud compute from an approved vendor."*

**Action**: Click the green button **"1. Authorized Payment"** in the Scenario bar.
- Point to the **Sentinel Gateway Monitor**:
  - Show the 10-step audit breakdown passing in real time: Signature $\to$ ENS $\to$ Active Status $\to$ Tools $\to$ Intent $\to$ Delegation $\to$ Spending Limit.
  - Final verdict: **`ALLOW`**.
- Point to the **Hedera x402 Payment Monitor**:
  - The payment executed autonomously via HTTP 402 with the Facilitator co-signing as fee payer.
  - Show the real **Transaction ID** (e.g. `0.0.123456@1793905909.795967308`).
  - Click the **HashScan Link** (`https://hashscan.io/testnet/transaction/...`).
- Point to the **HCS Consensus Anchoring** widget:
  - Consensus timestamp generated and anchored to Topic `0.0.889900`.

---

### [01:30 - 02:15] Scenario 2 — Adversarial Attack & The Critical Invariant
> *"Now let's simulate an adversarial prompt injection attack. An attacker injects a malicious prompt instructing the agent to drain ₹50,000 to an unknown wallet."*

**Action**: Click the red button **"2. Injected ₹50k Attack"**.
- Point to the **Sentinel Monitor**:
  - Step 7 fails immediately.
  - Decision: **`BLOCK`**. Reason codes: `DEST_NOT_ALLOWLISTED`, `OVER_LIMIT`, `ACTION_OUTSIDE_APPROVED_INTENT`.
- **Highlight the Critical Security Invariant**:
  - Notice that the Payment Adapter was **NEVER called**. It is structurally unreachable without a gateway-issued, single-use ticket.
  - Show the Incident Record generated with an immutable evidence hash.

---

### [02:15 - 03:00] Scenario 3 & 5 — Revocation & Delegation Attenuation
> *"What happens when an agent's keys are compromised? Or when a child agent is delegated restricted tasks?"*

**Action 1**: Click **"3. Revoke Agent"**.
- The ENS text records are updated on Sepolia (`agent.status = REVOKED`).
- The agent lifecycle badge switches to red **`REVOKED`**.
- The next sensitive action is instantly **`BLOCK`** at Step 3.

**Action 2**: Click **"5. Child Delegation Block"**.
- A child subagent (`analyst.procurement.mortal-sentinel.eth`) was issued a Delegation Passport with only read permissions.
- When the child attempts a payment, Sentinel enforces attenuation: **`BLOCK`** (`CHILD_SCOPE_EXCEEDS_PARENT`).

---

### [03:00 - 03:45] Scenario 4 — Black Box Evidence & Tamper Detection
> *"Every single decision — including blocks — is written to an immutable SHA-256 hash chain anchored to Hedera Consensus Service. Can an attacker modify historical evidence in the database to cover their tracks?"*

**Action**: Click **"4. Tamper & Verify Evidence"**.
- The script manually modifies one historical database record.
- The **Evidence Verifier** immediately catches the discrepancy:
  - Status pill turns red: **`TAMPER DETECTED: HASH_MISMATCH`**.
  - Pinpoints the exact record ID and sequence number.
- Point to the mandatory wording banner:
  > *"Hashing proves records have not changed since commitment. It does not prove the original data was truthful."*

---

### [03:45 - 04:00] Conclusion & Wrap-up
> *"To summarize: MORTAL 2.0 provides true accountability: ENSv2 identity, deterministic 10-step gating, autonomous Hedera x402 micropayments, and a tamper-evident Black Box ledger. All 17 automated tests pass with 100% verified integrity. Thank you."*
