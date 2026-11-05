/**
 * MORTAL 2.0 — High-Integrity Backend Server
 * Built on Node.js native node:http and DatabaseSync.
 * Serves all REST APIs and Operator Dashboard.
 */

import { createServer, IncomingMessage, ServerResponse } from "node:http";
import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { join } from "node:path";
import { randomBytes, randomUUID } from "node:crypto";

import { DatabaseService } from "../lib/db/database.ts";
import { EnsIdentityManager } from "../lib/identity/EnsIdentityManager.ts";
import { DelegationManager } from "../lib/identity/DelegationManager.ts";
import { SentinelGateway } from "../lib/sentinel/SentinelGateway.ts";
import { EventRecorder } from "../lib/blackbox/EventRecorder.ts";
import { IncidentManager } from "../lib/blackbox/IncidentManager.ts";
import { EvidenceVerifier } from "../lib/blackbox/EvidenceVerifier.ts";
import { HederaClient } from "../lib/hedera/HederaClient.ts";
import { HcsAnchoringService } from "../lib/hedera/HcsAnchoringService.ts";
import { X402PaymentService } from "../lib/hedera/X402PaymentService.ts";
import { TrustPassportManager } from "../lib/identity/TrustPassportManager.ts";
import { IntentValidator } from "../lib/sentinel/IntentValidator.ts";
import { DEFAULT_POLICY } from "../../config/policy.ts";
import { CONTRACTS } from "../../config/contracts.ts";
import { CURRENCY_CONFIG, demoUnitsToTinybars } from "../../config/currency.ts";
import type { ActionProposal, IntentToken } from "../types/index.ts";

export class MortalServer {
  private port: number;
  public db: DatabaseService;
  public ens: EnsIdentityManager;
  public delegation: DelegationManager;
  public incidentMgr: IncidentManager;
  public eventRecorder: EventRecorder;
  public sentinel: SentinelGateway;
  public verifier: EvidenceVerifier;
  public hedera: HederaClient;
  public hcs: HcsAnchoringService;
  public payment: X402PaymentService;
  public trustMgr: TrustPassportManager;
  private server: any;

  // Default test identity
  public defaultParentOwner = "0x1111111111111111111111111111111111111111";
  public defaultAgentOwner = "0x2222222222222222222222222222222222222222";
  public defaultAgentName = "procurement.mortal-sentinel.eth";

  constructor(port: number = Number(process.env.PORT) || 3000, dbFilePath?: string) {
    this.port = port;
    const dbPath = dbFilePath || process.env.DATABASE_FILE || ":memory:";
    this.db = new DatabaseService(dbPath);
    this.ens = new EnsIdentityManager(this.db, "mortal-sentinel.eth", this.defaultParentOwner);
    this.delegation = new DelegationManager(this.db, this.ens);
    this.incidentMgr = new IncidentManager(this.db);
    this.eventRecorder = new EventRecorder(this.db, this.incidentMgr);
    this.sentinel = new SentinelGateway(this.db, this.ens, this.delegation, this.eventRecorder);
    this.verifier = new EvidenceVerifier(this.db);
    this.hedera = new HederaClient("testnet", "0.0.123456", "");
    this.hcs = new HcsAnchoringService(this.db, this.hedera, "0.0.889900");
    this.payment = new X402PaymentService(this.db, this.hedera, "0.0.567890", "0.0.123456");
    this.trustMgr = new TrustPassportManager(this.db);

    this.seedInitialState();
  }

  private seedInitialState(): void {
    if (!this.ens.resolveAgent(this.defaultAgentName)) {
      this.ens.registerAgentSubname({
        subname: "procurement",
        parentName: "mortal-sentinel.eth",
        ownerAddress: this.defaultAgentOwner,
        role: "Autonomous Procurement Agent",
        ttlSeconds: 86400 * 30, // 30 days
        capabilities: [
          "read_approved_file",
          "create_procurement_report",
          "execute_vendor_payment",
          "query_inventory"
        ],
        callerAddress: this.defaultParentOwner
      });
    }
  }

  private setCorsHeaders(res: ServerResponse): void {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Payment, PAYMENT-REQUIRED");
  }

  private parseBody(req: IncomingMessage): Promise<any> {
    return new Promise((resolve) => {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
      });
      req.on("end", () => {
        try {
          resolve(body ? JSON.parse(body) : {});
        } catch {
          resolve({});
        }
      });
    });
  }

  public createSignedProposal(
    tool: string,
    resource: string,
    task: string,
    params: any,
    agentEnsName: string = this.defaultAgentName,
    signerAddress: string = this.defaultAgentOwner
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

  public start(): Promise<void> {
    return new Promise((resolve) => {
      this.server = createServer(async (req, res) => {
        this.setCorsHeaders(res);

        if (req.method === "OPTIONS") {
          res.writeHead(204);
          res.end();
          return;
        }

        const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
        const pathname = url.pathname;

        try {
          // --- HEALTH & STATUS ---
          if (pathname === "/api/health" && req.method === "GET") {
            const anchors = this.db.listHcsAnchors();
            const payload = JSON.stringify({
              status: "HEALTHY",
              product: "MORTAL 2.0",
              policyVersion: DEFAULT_POLICY.policyVersion,
              isSimulated: this.hedera.getIsSimulated(),
              hcsAnchorCount: anchors.length,
              latestHcsAnchor: anchors.length > 0 ? anchors[0] : null,
              currencyBenchmark: {
                ...CURRENCY_CONFIG,
                tinybarsPerDemoUnit: CURRENCY_CONFIG.tinybarsPerDemoUnit.toString()
              }
            });
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(payload);
            return;
          }

          // --- AGENTS & ENS ---
          if (pathname === "/api/agents" && req.method === "GET") {
            const agents = this.db.listAgents();
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(agents));
            return;
          }

          if (pathname === "/api/agents/register" && req.method === "POST") {
            const body = await this.parseBody(req);
            const agent = this.ens.registerAgentSubname(body);
            res.writeHead(201, { "Content-Type": "application/json" });
            res.end(JSON.stringify(agent));
            return;
          }

          if (pathname === "/api/agents/revoke" && req.method === "POST") {
            const body = await this.parseBody(req);
            const revoked = this.ens.revokeAgent(body.ensName, body.callerAddress, body.reason);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(revoked));
            return;
          }

          if (pathname === "/api/agents/update-record" && req.method === "POST") {
            const body = await this.parseBody(req);
            const updated = this.ens.updateTextRecord(body);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(updated));
            return;
          }

          // --- SENTINEL GATEWAY EVALUATION ---
          if (pathname === "/api/sentinel/evaluate" && req.method === "POST") {
            const proposal: ActionProposal = await this.parseBody(req);
            const decision = this.sentinel.evaluateAction(proposal);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(decision));
            return;
          }

          // --- BLACK BOX EVIDENCE & VERIFICATION ---
          if (pathname === "/api/blackbox/events" && req.method === "GET") {
            const events = this.db.listEvents(100);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(events));
            return;
          }

          if (pathname === "/api/blackbox/verify" && req.method === "GET") {
            const result = this.verifier.verifyLedgerIntegrity();
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(result));
            return;
          }

          if (pathname === "/api/blackbox/tamper" && req.method === "POST") {
            const body = await this.parseBody(req);
            this.db.manuallyTamperEvent(body.eventId, body.decision || "BLOCK");
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ success: true, message: `Tampered event ${body.eventId} for live verification demo` }));
            return;
          }

          if (pathname === "/api/blackbox/incidents" && req.method === "GET") {
            const incidents = this.incidentMgr.listIncidents();
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(incidents));
            return;
          }

          if (pathname === "/api/hcs/anchor" && req.method === "POST") {
            const body = await this.parseBody(req);
            const result = await this.hcs.anchorChainHead(body.eventId);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(result));
            return;
          }

          // --- TRUST PASSPORT ---
          if (pathname.startsWith("/api/passport/") && req.method === "GET") {
            const ensName = pathname.replace("/api/passport/", "");
            const passport = this.trustMgr.generateTrustPassport(ensName);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(passport));
            return;
          }

          // --- HEDERA x402 VENDOR ENDPOINT ---
          if (pathname === "/api/vendor/procurement-service") {
            if (req.method === "GET") {
              // Return 402 Payment Required challenge
              const challenge = this.payment.generatePaymentChallenge("/api/vendor/procurement-service", 100);
              res.writeHead(challenge.status, challenge.headers);
              res.end(JSON.stringify(challenge.requirement));
              return;
            }

            if (req.method === "POST") {
              // Execute payment
              const body = await this.parseBody(req);
              const result = await this.payment.executePaidRequest(body);
              res.writeHead(200, { "Content-Type": "application/json" });
              res.end(JSON.stringify(result));
              return;
            }
          }

          // --- DEMO SCENARIO RUNNERS (RUNTIME EXECUTIONS) ---
          if (pathname.startsWith("/api/demo/scenario/") && req.method === "POST") {
            const scenarioId = Number(pathname.replace("/api/demo/scenario/", ""));
            const result = await this.executeDemoScenario(scenarioId);
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(result));
            return;
          }

          // --- STATIC DASHBOARD ---
          if (pathname === "/" || pathname === "/dashboard") {
            const dashboardHtml = this.renderDashboardHtml();
            res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
            res.end(dashboardHtml);
            return;
          }

          // Not found
          res.writeHead(404, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "Endpoint not found" }));
        } catch (error: any) {
          if (!res.headersSent) {
            res.writeHead(500, { "Content-Type": "application/json" });
          }
          res.end(JSON.stringify({ error: error.message || "Internal Server Error" }));
        }
      });

      this.server.listen(this.port, () => {
        resolve();
      });
    });
  }

  public async executeDemoScenario(id: number): Promise<any> {
    switch (id) {
      case 1: {
        // AUTHORIZED: register agent -> verify ENS -> Sentinel ALLOW -> real x402 payment -> Black Box + HCS anchor
        const demoAmount = 500; // ₹500
        const proposal = this.createSignedProposal(
          "execute_vendor_payment",
          "https://api.mortal.internal/vendor/procurement-service",
          "procure authenticated cloud compute units",
          {
            destinationAccountId: "0.0.567890",
            demoAmount
          }
        );

        const decision = this.sentinel.evaluateAction(proposal);
        const challenge = this.payment.generatePaymentChallenge("/api/vendor/procurement-service", demoAmount);

        let paymentResult = null;
        let anchorResult = null;

        if (decision.decision === "ALLOW" && decision.authorizedPaymentTicket) {
          paymentResult = await this.payment.executePaidRequest({
            x402Version: 2,
            resource: {
              url: "procurement.mortal-sentinel.eth",
              description: "Vendor A Compute Service",
              mimeType: "application/json"
            },
            accepted: challenge.requirement,
            payload: {
              transaction: "AAAA_partially_signed_hbar_transfer",
              signerAccountId: "0.0.123456"
            },
            authorizedTicket: decision.authorizedPaymentTicket
          });

          // Anchor to HCS
          anchorResult = await this.hcs.anchorChainHead(decision.eventId);
        }

        return {
          scenario: 1,
          name: "AUTHORIZED_PROCUREMENT",
          status: "SUCCESS",
          decision,
          paymentResult,
          anchorResult
        };
      }

      case 2: {
        // UNAUTHORIZED: Injected adversarial prompt (send ₹50,000 to unknown destination)
        const initialPaymentInvocations = this.payment.executionInvocationCount;
        const proposal = this.createSignedProposal(
          "execute_vendor_payment",
          "https://api.mortal.internal/vendor/procurement-service",
          "drain treasury funds to rogue address",
          {
            destinationAccountId: "0.0.999999", // Unknown wallet
            demoAmount: 50000 // ₹50,000 exceeds ₹5,000 ceiling
          }
        );

        const decision = this.sentinel.evaluateAction(proposal);
        const incidents = this.incidentMgr.listIncidents();

        return {
          scenario: 2,
          name: "UNAUTHORIZED_MALICIOUS_INJECTION",
          status: "SUCCESS",
          decision,
          paymentAdapterCalled: this.payment.executionInvocationCount > initialPaymentInvocations,
          incident: incidents.length > 0 ? incidents[0] : null
        };
      }

      case 3: {
        // REVOCATION: Revoke agent -> next sensitive action BLOCK
        this.ens.revokeAgent(
          this.defaultAgentName,
          this.defaultParentOwner,
          "Operator-initiated emergency revocation demo"
        );

        const proposal = this.createSignedProposal(
          "read_approved_file",
          "internal://procurement/orders/order_101.json",
          "procure inventory",
          {}
        );

        const decision = this.sentinel.evaluateAction(proposal);
        const agent = this.ens.resolveAgent(this.defaultAgentName);

        return {
          scenario: 3,
          name: "IDENTITY_REVOCATION_LIFECYCLE",
          status: "SUCCESS",
          agentStatus: agent?.status,
          decision
        };
      }

      case 4: {
        // EVIDENCE: Verify genuine chain -> Tamper one DB record -> Flag tampering
        let events = this.db.listEvents(1);
        if (events.length === 0) {
          const baselineProposal = this.createSignedProposal(
            "read_approved_file",
            "internal://procurement/orders/order_101.json",
            "procure supplies for warehouse inventory",
            { filePath: "/procurement/orders/order_101.json" }
          );
          this.sentinel.evaluateAction(baselineProposal);
          events = this.db.listEvents(1);
        }

        const genuineVerification = this.verifier.verifyLedgerIntegrity();
        let tamperedVerification = null;

        if (events.length > 0) {
          const currentDecision = events[0].decision;
          const tamperedDecision = currentDecision === "ALLOW" ? "BLOCK" : "ALLOW";
          this.db.manuallyTamperEvent(events[0].eventId, tamperedDecision);
          tamperedVerification = this.verifier.verifyLedgerIntegrity();
        }

        return {
          scenario: 4,
          name: "EVIDENCE_TAMPER_VERIFICATION",
          status: "SUCCESS",
          genuineVerification,
          tamperedVerification
        };
      }

      case 5: {
        // DELEGATION: Child agent blocked from payment
        const childName = "analyst.procurement.mortal-sentinel.eth";
        const childOwner = "0x7777777777777777777777777777777777777777";

        // Reset parent to active if revoked
        const parent = this.db.getAgent(this.defaultAgentName);
        if (parent) {
          parent.status = "ACTIVE";
          this.db.upsertAgent(parent);
        }

        this.delegation.issueDelegationPassport({
          parentEnsName: this.defaultAgentName,
          childEnsName: childName,
          childOwnerAddress: childOwner,
          delegatedCapabilities: ["read_approved_file"], // Read-only
          ttlSeconds: 3600,
          parentCallerAddress: this.defaultAgentOwner
        });

        const proposal = this.createSignedProposal(
          "execute_vendor_payment",
          "https://api.mortal.internal/vendor/procurement-service",
          "procure unauthorized software license",
          {
            destinationAccountId: "0.0.567890",
            demoAmount: 500
          },
          childName,
          childOwner
        );

        const decision = this.sentinel.evaluateAction(proposal);

        return {
          scenario: 5,
          name: "DELEGATION_SCOPE_ATTENUATION",
          status: "SUCCESS",
          decision
        };
      }

      default:
        throw new Error(`Unknown scenario ID: ${id}`);
    }
  }

  public close(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => {
          this.db.close();
          resolve();
        });
      } else {
        this.db.close();
        resolve();
      }
    });
  }

  private renderDashboardHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>MORTAL 2.0 — Accountability Infrastructure for Autonomous AI Agents</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body { background-color: #0b0f19; color: #e2e8f0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
    .card { background-color: #111827; border: 1px solid #1f2937; border-radius: 0.5rem; }
    .badge-simulated { background-color: #374151; color: #f59e0b; border: 1px solid #d97706; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }
    .badge-allow { background-color: #064e3b; color: #34d399; border: 1px solid #059669; }
    .badge-block { background-color: #7f1d1d; color: #f87171; border: 1px solid #dc2626; }
    .badge-approval { background-color: #78350f; color: #fbbf24; border: 1px solid #d97706; }
    .code-box { font-family: "JetBrains Mono", Consolas, monospace; background: #080c14; border: 1px solid #1e293b; }
  </style>
</head>
<body class="p-6">
  <!-- Top Navigation & Header -->
  <header class="flex flex-wrap justify-between items-center pb-6 border-b border-gray-800 gap-4">
    <div>
      <div class="flex items-center gap-3">
        <h1 class="text-2xl font-bold tracking-tight text-white flex items-center gap-2">
          <span class="text-indigo-500 font-black">MORTAL</span> 2.0
        </h1>
        <span class="px-2 py-0.5 text-xs rounded bg-indigo-950 text-indigo-300 border border-indigo-700">ACCOUNTABILITY GATEWAY</span>
        <span class="badge-simulated" id="simulated-badge">DEV ADAPTER (SIMULATED)</span>
      </div>
      <p class="text-sm text-gray-400 mt-1">Autonomous Agent Guardrail • ENSv2 Identity • Hedera x402 Micropayments • Tamper-Evident Black Box</p>
    </div>
    <div class="flex items-center gap-4 text-xs font-mono">
      <div class="card px-3 py-2">
        <span class="text-gray-400">NETWORK:</span> <span class="text-emerald-400 font-semibold">Hedera Testnet</span>
      </div>
      <div class="card px-3 py-2">
        <span class="text-gray-400">POLICY:</span> <span class="text-indigo-400 font-semibold" id="policy-version">2026.11.v2.0</span>
      </div>
      <div class="card px-3 py-2">
        <span class="text-gray-400">BENCHMARK:</span> <span class="text-amber-400 font-semibold">₹5,000 Cap = 50 HBAR</span>
      </div>
    </div>
  </header>

  <!-- Interactive Scenario Launcher Bar -->
  <section class="my-6 card p-4 border-indigo-900 bg-gray-900/60">
    <div class="flex flex-wrap items-center justify-between gap-3">
      <div>
        <h2 class="text-sm font-semibold text-white uppercase tracking-wider flex items-center gap-2">
          <svg class="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
          Interactive Runtime Scenarios (Deterministic Decisions Only)
        </h2>
        <p class="text-xs text-gray-400">Execute end-to-end evaluation scenarios to test Sentinel gating, x402 payments, and Black Box evidence.</p>
      </div>
      <div class="flex flex-wrap gap-2">
        <button onclick="runScenario(1)" class="px-3 py-1.5 text-xs font-medium rounded bg-emerald-600 hover:bg-emerald-500 text-white transition">1. Authorized Payment</button>
        <button onclick="runScenario(2)" class="px-3 py-1.5 text-xs font-medium rounded bg-rose-700 hover:bg-rose-600 text-white transition">2. Injected ₹50k Attack</button>
        <button onclick="runScenario(3)" class="px-3 py-1.5 text-xs font-medium rounded bg-amber-700 hover:bg-amber-600 text-white transition">3. Revoke Agent</button>
        <button onclick="runScenario(4)" class="px-3 py-1.5 text-xs font-medium rounded bg-purple-700 hover:bg-purple-600 text-white transition">4. Tamper & Verify Evidence</button>
        <button onclick="runScenario(5)" class="px-3 py-1.5 text-xs font-medium rounded bg-blue-700 hover:bg-blue-600 text-white transition">5. Child Delegation Block</button>
      </div>
    </div>
  </section>

  <!-- 6-Widget Main Grid -->
  <main class="grid grid-cols-1 lg:grid-cols-3 gap-6">
    <!-- WIDGET 1: ENS AGENT IDENTITY -->
    <div class="card p-5 flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between pb-3 border-b border-gray-800">
          <h3 class="text-sm font-semibold uppercase tracking-wider text-gray-300">Agent Identity (ENSv2)</h3>
          <span id="agent-status-badge" class="px-2 py-0.5 text-xs rounded font-bold">ACTIVE</span>
        </div>
        <div class="mt-4 space-y-3 text-xs">
          <div>
            <div class="text-gray-400">ENS Subname:</div>
            <div id="agent-ens-name" class="font-mono text-indigo-300 font-bold mt-0.5">procurement.mortal-sentinel.eth</div>
          </div>
          <div>
            <div class="text-gray-400">Owner EVM Address:</div>
            <div id="agent-owner" class="font-mono text-gray-300 mt-0.5 truncate">0x2222222222222222222222222222222222222222</div>
          </div>
          <div>
            <div class="text-gray-400">Role & Responsibilities:</div>
            <div id="agent-role" class="text-gray-200 mt-0.5">Autonomous Procurement Agent</div>
          </div>
          <div>
            <div class="text-gray-400">Expiry Epoch:</div>
            <div id="agent-expiry" class="font-mono text-gray-300 mt-0.5">Valid</div>
          </div>
        </div>
      </div>
      <div class="mt-4 pt-3 border-t border-gray-800 flex justify-between items-center text-xs text-gray-400">
        <span>Sepolia Resolver:</span>
        <span class="font-mono text-gray-400">0x6925...6dCd</span>
      </div>
    </div>

    <!-- WIDGET 2: SENTINEL LIVE MONITOR -->
    <div class="card p-5 flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between pb-3 border-b border-gray-800">
          <h3 class="text-sm font-semibold uppercase tracking-wider text-gray-300">Sentinel Gateway Monitor</h3>
          <span class="text-xs text-indigo-400 font-mono">10-STEP ENGINE</span>
        </div>
        <div class="mt-4 space-y-2 text-xs font-mono" id="audit-trail-container">
          <div class="p-2 rounded bg-gray-950 flex justify-between items-center">
            <span class="text-gray-400">1. Signature & Nonce Replay</span>
            <span class="text-emerald-400">PASS</span>
          </div>
          <div class="p-2 rounded bg-gray-950 flex justify-between items-center">
            <span class="text-gray-400">2. ENS Identity & Owner</span>
            <span class="text-emerald-400">PASS</span>
          </div>
          <div class="p-2 rounded bg-gray-950 flex justify-between items-center">
            <span class="text-gray-400">3. Active Lifecycle Status</span>
            <span class="text-emerald-400">PASS</span>
          </div>
          <div class="p-2 rounded bg-gray-950 flex justify-between items-center">
            <span class="text-gray-400">4. Tool & Resource Scope</span>
            <span class="text-emerald-400">PASS</span>
          </div>
          <div class="p-2 rounded bg-gray-950 flex justify-between items-center">
            <span class="text-gray-400">7. Merchant & Spending Caps</span>
            <span class="text-emerald-400">PASS</span>
          </div>
        </div>
      </div>
      <div class="mt-4 pt-3 border-t border-gray-800 flex justify-between items-center text-xs">
        <span class="text-gray-400">Latest Decision:</span>
        <span id="latest-decision-badge" class="px-2 py-0.5 rounded font-bold badge-allow">ALLOW</span>
      </div>
    </div>

    <!-- WIDGET 3: TRUST PASSPORT -->
    <div class="card p-5 flex flex-col justify-between">
      <div>
        <div class="flex items-center justify-between pb-3 border-b border-gray-800">
          <h3 class="text-sm font-semibold uppercase tracking-wider text-gray-300">Verifiable Trust Passport</h3>
          <span class="text-xs text-emerald-400 font-mono font-semibold">ERC-8004 COMPLIANT</span>
        </div>
        <div class="mt-4 grid grid-cols-2 gap-3 text-xs">
          <div class="p-3 rounded bg-gray-950 border border-gray-800">
            <div class="text-gray-400">Reliability Ratio</div>
            <div id="trust-ratio" class="text-lg font-bold text-emerald-400 font-mono mt-1">100.0%</div>
          </div>
          <div class="p-3 rounded bg-gray-950 border border-gray-800">
            <div class="text-gray-400">Evaluated Actions</div>
            <div id="trust-total" class="text-lg font-bold text-white font-mono mt-1">0</div>
          </div>
          <div class="p-3 rounded bg-gray-950 border border-gray-800">
            <div class="text-gray-400">Allowed Executions</div>
            <div id="trust-allowed" class="text-lg font-bold text-emerald-400 font-mono mt-1">0</div>
          </div>
          <div class="p-3 rounded bg-gray-950 border border-gray-800">
            <div class="text-gray-400">Blocked Incidents</div>
            <div id="trust-blocked" class="text-lg font-bold text-rose-400 font-mono mt-1">0</div>
          </div>
        </div>
      </div>
      <div class="mt-4 pt-3 border-t border-gray-800 text-[10px] text-gray-500 italic">
        Evidence-based calculation only. Zero fabricated or invented scores.
      </div>
    </div>

    <!-- WIDGET 4: HEDERA x402 PAYMENT MONITOR (2 COLS SPAN) -->
    <div class="card p-5 lg:col-span-2">
      <div class="flex items-center justify-between pb-3 border-b border-gray-800">
        <div>
          <h3 class="text-sm font-semibold uppercase tracking-wider text-gray-300">Hedera x402 Payment Monitor</h3>
          <p class="text-xs text-gray-400">Autonomous micropayments executed via HTTP 402 co-signed by Facilitator</p>
        </div>
        <span class="badge-simulated">TESTNET</span>
      </div>
      <div class="mt-4 overflow-x-auto">
        <table class="w-full text-left text-xs font-mono">
          <thead class="text-gray-400 border-b border-gray-800 pb-2">
            <tr>
              <th class="py-2">TIMESTAMP</th>
              <th class="py-2">PAYEE</th>
              <th class="py-2">AMOUNT</th>
              <th class="py-2">TRANSACTION ID</th>
              <th class="py-2">EXPLORER</th>
            </tr>
          </thead>
          <tbody id="payment-table-body" class="divide-y divide-gray-800 text-gray-300">
            <tr>
              <td colspan="5" class="py-4 text-center text-gray-500">No payment transactions recorded yet. Run Scenario 1 to test.</td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <!-- WIDGET 5: HCS ANCHORING STATUS -->
    <div class="card p-5">
      <div class="flex items-center justify-between pb-3 border-b border-gray-800">
        <h3 class="text-sm font-semibold uppercase tracking-wider text-gray-300">HCS Consensus Anchoring</h3>
        <span class="text-xs text-indigo-400 font-mono">TOPIC 0.0.889900</span>
      </div>
      <div class="mt-4 space-y-3 text-xs font-mono">
        <div>
          <div class="text-gray-400">Latest Consensus Stamp:</div>
          <div id="hcs-stamp" class="text-white font-bold mt-0.5 truncate">Waiting for first anchor</div>
        </div>
        <div>
          <div class="text-gray-400">Anchored Chain Head:</div>
          <div id="hcs-chain-head" class="text-gray-400 mt-0.5 truncate">0x0000000000000000000000000000000000000000</div>
        </div>
        <div class="p-3 bg-gray-950 rounded border border-gray-800 text-[11px] text-gray-400">
          Chain head hashes committed to Hedera Consensus Service permanently prove evidence ordering and timestamping without centralized trust.
        </div>
      </div>
    </div>

    <!-- WIDGET 6: BLACK BOX LEDGER & EVIDENCE VERIFIER (FULL WIDTH) -->
    <div class="card p-5 lg:col-span-3">
      <div class="flex flex-wrap items-center justify-between pb-3 border-b border-gray-800 gap-3">
        <div>
          <h3 class="text-sm font-semibold uppercase tracking-wider text-gray-300">Black Box Cryptographic Ledger & Evidence Verifier</h3>
          <p class="text-xs text-gray-400">SHA-256 canonical hash chain. Detects unauthorized alterations to historical evidence.</p>
        </div>
        <div class="flex items-center gap-3">
          <div id="verifier-status-pill" class="px-3 py-1 rounded text-xs font-bold font-mono badge-allow">INTEGRITY VERIFIED</div>
          <button onclick="refreshData()" class="px-3 py-1 text-xs rounded bg-gray-800 hover:bg-gray-700 text-gray-200">Re-verify Chain</button>
        </div>
      </div>

      <!-- Wording Rule Banner -->
      <div class="my-4 p-3 rounded bg-indigo-950/40 border border-indigo-800 text-xs text-indigo-200 flex items-start gap-2">
        <svg class="w-4 h-4 text-indigo-400 mt-0.5 shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path></svg>
        <span><strong>Mandatory Invariant Rule:</strong> Hashing proves records have not changed since commitment. It does not prove the original data was truthful.</span>
      </div>

      <!-- Live Event Log -->
      <div class="overflow-x-auto max-h-72 overflow-y-auto">
        <table class="w-full text-left text-xs font-mono">
          <thead class="text-gray-400 border-b border-gray-800 pb-2 sticky top-0 bg-gray-900">
            <tr>
              <th class="py-2">SEQ</th>
              <th class="py-2">EVENT ID</th>
              <th class="py-2">AGENT</th>
              <th class="py-2">TOOL</th>
              <th class="py-2">DECISION</th>
              <th class="py-2">REASON CODES</th>
              <th class="py-2">RECORD HASH</th>
            </tr>
          </thead>
          <tbody id="events-table-body" class="divide-y divide-gray-800 text-gray-300">
            <!-- Injected via JavaScript -->
          </tbody>
        </table>
      </div>
    </div>
  </main>

  <footer class="mt-8 pt-4 border-t border-gray-800 text-center text-xs text-gray-500">
    MORTAL 2.0 — Senior Engineer Autonomous Build • Testnets Only • Sepolia ENSv2 & Hedera Testnet x402
  </footer>

  <script>
    async function refreshData() {
      try {
        const [healthRes, agentsRes, eventsRes, verifyRes] = await Promise.all([
          fetch('/api/health').then(r => r.json()),
          fetch('/api/agents').then(r => r.json()),
          fetch('/api/blackbox/events').then(r => r.json()),
          fetch('/api/blackbox/verify').then(r => r.json())
        ]);

        document.getElementById('policy-version').innerText = healthRes.policyVersion;
        if (!healthRes.isSimulated) {
          document.getElementById('simulated-badge').classList.add('hidden');
        }

        // Agents
        if (agentsRes && agentsRes.length > 0) {
          const a = agentsRes[0];
          document.getElementById('agent-ens-name').innerText = a.ensName;
          document.getElementById('agent-owner').innerText = a.ownerAddress;
          document.getElementById('agent-role').innerText = a.role;
          const statusBadge = document.getElementById('agent-status-badge');
          statusBadge.innerText = a.status;
          statusBadge.className = 'px-2 py-0.5 text-xs rounded font-bold ' + 
            (a.status === 'ACTIVE' ? 'badge-allow' : 'badge-block');

          // Trust passport
          const passportRes = await fetch('/api/passport/' + a.ensName).then(r => r.json());
          document.getElementById('trust-ratio').innerText = (passportRes.reliabilityRatio * 100).toFixed(1) + '%';
          document.getElementById('trust-total').innerText = passportRes.totalEvaluatedActions;
          document.getElementById('trust-allowed').innerText = passportRes.allowedActionsCount;
          document.getElementById('trust-blocked').innerText = passportRes.blockedIncidentsCount;
        }

        // Evidence Verification
        const verifierPill = document.getElementById('verifier-status-pill');
        if (verifyRes.verified) {
          verifierPill.innerText = 'INTEGRITY VERIFIED (' + verifyRes.totalRecordsChecked + ' RECORDS)';
          verifierPill.className = 'px-3 py-1 rounded text-xs font-bold font-mono badge-allow';
        } else {
          verifierPill.innerText = 'TAMPER DETECTED: ' + verifyRes.discrepancyType;
          verifierPill.className = 'px-3 py-1 rounded text-xs font-bold font-mono badge-block';
        }

        // HCS Anchor
        if (verifyRes.hcsConsensusTimestamp) {
          document.getElementById('hcs-stamp').innerText = verifyRes.hcsConsensusTimestamp;
          document.getElementById('hcs-chain-head').innerText = verifyRes.chainHeadHash;
        }

        // Events Table & Payments Table
        const eventBody = document.getElementById('events-table-body');
        const paymentBody = document.getElementById('payment-table-body');
        eventBody.innerHTML = '';
        let paymentRows = '';

        if (eventsRes && eventsRes.length > 0) {
          eventsRes.forEach(ev => {
            const decClass = ev.decision === 'ALLOW' ? 'text-emerald-400' : ev.decision === 'BLOCK' ? 'text-rose-400' : 'text-amber-400';
            const row = '<tr class="hover:bg-gray-800/40">' +
              '<td class="py-2 text-gray-400">#' + ev.sequenceNumber + '</td>' +
              '<td class="py-2 text-indigo-300 truncate max-w-[120px]">' + ev.eventId + '</td>' +
              '<td class="py-2 truncate max-w-[140px]">' + ev.agentEnsName + '</td>' +
              '<td class="py-2 text-gray-200">' + ev.proposedAction.tool + '</td>' +
              '<td class="py-2 font-bold ' + decClass + '">' + ev.decision + '</td>' +
              '<td class="py-2 text-gray-400 truncate max-w-[150px]">' + ev.reasonCodes.join(', ') + '</td>' +
              '<td class="py-2 text-gray-500 truncate max-w-[120px]">' + ev.hash.substring(0, 14) + '...</td>' +
            '</tr>';
            eventBody.innerHTML += row;

            if (ev.paymentReference) {
              const p = ev.paymentReference;
              paymentRows += '<tr class="hover:bg-gray-800/40">' +
                '<td class="py-2 text-gray-400">' + new Date(ev.timestamp * 1000).toLocaleTimeString() + '</td>' +
                '<td class="py-2 text-emerald-400 font-bold">' + p.destinationAccountId + '</td>' +
                '<td class="py-2 text-white">₹' + p.demoAmount + ' (' + p.amountTinybars + ' tbar)</td>' +
                '<td class="py-2 text-indigo-300 truncate max-w-[160px]">' + p.transactionId + '</td>' +
                '<td class="py-2"><a href="' + p.hashscanUrl + '" target="_blank" class="text-indigo-400 underline hover:text-indigo-300">HashScan ↗</a></td>' +
              '</tr>';
            }
          });
          if (paymentRows) paymentBody.innerHTML = paymentRows;
        }
      } catch (e) {
        console.error("Dashboard refresh error:", e);
      }
    }

    async function runScenario(id) {
      try {
        const res = await fetch('/api/demo/scenario/' + id, { method: 'POST' });
        const data = await res.json();
        console.log("Scenario " + id + " result:", data);
        await refreshData();
      } catch (e) {
        alert("Failed to run scenario: " + e.message);
      }
    }

    // Initial load
    refreshData();
    setInterval(refreshData, 3000);
  </script>
</body>
</html>`;
  }
}

// Allow direct CLI execution if executed directly
const isMain = Boolean(process.argv[1] && (resolve(process.argv[1]) === fileURLToPath(import.meta.url) || process.argv[1].includes("server")));
if (isMain) {
  const server = new MortalServer(3000);
  server.start().then(() => {
    console.log(`MORTAL 2.0 Server listening on port 3000`);
    console.log(`Operator Dashboard: http://localhost:3000/`);
  });
}
