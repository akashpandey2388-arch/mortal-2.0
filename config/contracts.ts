/**
 * MORTAL 2.0 — Network & Smart Contract Registry
 * Reference addresses verified from official ENS and Hedera documentation.
 */

export const CONTRACTS = {
  sepolia: {
    chainId: 11155111,
    nameWrapper: "0xab50971078225D365994dc1Edcb9b7FD72Bb4862",
    publicResolver: "0x6925affDa98274FE0376250187CCC4aC62866dCd",
    ensRegistry: "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e",
    universalResolver: "0xeEeEEEeE14D718C2B47D9923Deab1335E144EeEe",
    parentName: "mortal-sentinel.eth",
    agentSubname: "procurement.mortal-sentinel.eth",
    rpcUrl: "https://rpc.sepolia.org"
  },
  hedera: {
    network: "testnet",
    caip2: "hedera:testnet",
    mirrorNodeUrl: "https://testnet.mirrornode.hedera.com",
    hashscanBaseUrl: "https://hashscan.io/testnet",
    defaultVendorAccountId: "0.0.567890",
    defaultFacilitatorAccountId: "0.0.123456",
    hcsAuditTopicMemo: "MORTAL-2.0-Audit-Ledger"
  }
};
