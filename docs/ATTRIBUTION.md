# MORTAL 2.0 — Code and Architecture Attribution

MORTAL 2.0 preserves third-party intellectual property and openly acknowledges foundational work:

## 1. open-agents-toolkit & ERC-8004
- **Author**: Julien A. (@cladjules)
- **Repository**: [cladjules/open-agents-toolkit](https://github.com/cladjules/open-agents-toolkit)
- **Concepts Reused/Adapted**:
  - Concept of on-chain agent identity registered via ENS subnames and metadata text records.
  - ERC-8004 standard concepts for decentralized agent identity and verifiable reputation passports.
- **MORTAL Custom Additions**:
  - Independent 10-step deterministic Sentinel policy enforcement gateway.
  - Hedera x402 payment engine and HCS audit hash-chain anchoring.
  - Tamper-evident Black Box evidence verification engine.

## 2. ENS (Ethereum Name Service)
- **Organization**: ENS Labs / True Names LTD
- **Repository**: [ensdomains/ens-contracts](https://github.com/ensdomains/ens-contracts)
- **Contracts**: NameWrapper (ERC-1155), PublicResolver, UniversalResolver on Sepolia testnet.

## 3. Hedera & x402 Payment Standard
- **Organizations**: Hedera Hashgraph & x402 Foundation
- **Repositories**: [x402-foundation/x402](https://github.com/x402-foundation/x402), [hashgraph/hedera-sdk-js](https://github.com/hashgraph/hedera-sdk-js)
- **Specifications**: HTTP 402 Payment Required exact scheme specification for Hedera (`scheme_exact_hedera.md`).
