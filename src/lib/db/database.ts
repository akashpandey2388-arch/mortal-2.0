/**
 * MORTAL 2.0 — High-Integrity Database Layer
 * Built on Node.js 24 native node:sqlite (DatabaseSync)
 * Provides persistent SQLite storage or in-memory testing mode.
 */

import { DatabaseSync } from "node:sqlite";
import type {
  AgentIdentity,
  BlackBoxEvent,
  IncidentRecord,
  DelegationPassport,
  DecisionType,
  ReasonCode
} from "../../types/index.ts";

export class DatabaseService {
  private db: DatabaseSync;
  private filePath: string;

  constructor(filePath: string = ":memory:") {
    this.filePath = filePath;
    this.db = new DatabaseSync(filePath);
    this.initializeSchema();
  }

  private initializeSchema(): void {
    // 1. Agents Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS agents (
        ens_name TEXT PRIMARY KEY,
        owner_address TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL,
        expiry_timestamp INTEGER NOT NULL,
        registered_at INTEGER NOT NULL,
        text_records_json TEXT NOT NULL,
        is_simulated INTEGER NOT NULL DEFAULT 0,
        delegation_depth INTEGER DEFAULT 0,
        parent_ens_name TEXT
      );
    `);

    // 2. Nonce Replay Protection Store
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS nonces (
        nonce TEXT PRIMARY KEY,
        token_id TEXT NOT NULL,
        agent_ens_name TEXT NOT NULL,
        timestamp INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_nonces_agent ON nonces (agent_ens_name);
    `);

    // 3. Black Box Cryptographic Event Ledger (Hash Chain)
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS events (
        sequence_number INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        prev_hash TEXT NOT NULL,
        hash TEXT NOT NULL,
        timestamp INTEGER NOT NULL,
        agent_ens_name TEXT NOT NULL,
        approved_intent TEXT NOT NULL,
        policy_version TEXT NOT NULL,
        proposed_action_json TEXT NOT NULL,
        decision TEXT NOT NULL,
        reason_codes_json TEXT NOT NULL,
        human_approval_json TEXT,
        execution_result_json TEXT,
        payment_reference_json TEXT,
        hcs_anchor_json TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_events_agent ON events (agent_ens_name);
      CREATE INDEX IF NOT EXISTS idx_events_hash ON events (hash);
    `);

    // 4. Incidents Table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS incidents (
        incident_id TEXT PRIMARY KEY,
        event_id TEXT NOT NULL,
        agent_ens_name TEXT NOT NULL,
        severity TEXT NOT NULL,
        reason_codes_json TEXT NOT NULL,
        description TEXT NOT NULL,
        detected_at INTEGER NOT NULL,
        status TEXT NOT NULL,
        evidence_hash TEXT NOT NULL,
        hcs_anchor_json TEXT,
        FOREIGN KEY(event_id) REFERENCES events(event_id)
      );
    `);

    // 5. Single-use Payment Authorization Tickets
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS payment_tickets (
        ticket_id TEXT PRIMARY KEY,
        agent_ens_name TEXT NOT NULL,
        action_id TEXT NOT NULL,
        destination_account_id TEXT NOT NULL,
        amount_tinybars TEXT NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0
      );
    `);

    // 6. Delegation Passports
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS delegations (
        child_ens_name TEXT PRIMARY KEY,
        parent_ens_name TEXT NOT NULL,
        delegated_capabilities_json TEXT NOT NULL,
        depth INTEGER NOT NULL,
        issued_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        parent_signature TEXT NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0
      );
    `);

    // 7. HCS Commitments
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS hcs_anchors (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        topic_id TEXT NOT NULL,
        sequence_number INTEGER NOT NULL,
        consensus_timestamp TEXT NOT NULL,
        chain_head_hash TEXT NOT NULL,
        event_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        is_simulated INTEGER NOT NULL DEFAULT 0
      );
    `);
  }

  // --- Agent Operations ---
  public upsertAgent(agent: AgentIdentity): void {
    const stmt = this.db.prepare(`
      INSERT INTO agents (
        ens_name, owner_address, role, status, expiry_timestamp,
        registered_at, text_records_json, is_simulated, delegation_depth, parent_ens_name
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(ens_name) DO UPDATE SET
        owner_address=excluded.owner_address,
        role=excluded.role,
        status=excluded.status,
        expiry_timestamp=excluded.expiry_timestamp,
        text_records_json=excluded.text_records_json,
        is_simulated=excluded.is_simulated,
        delegation_depth=excluded.delegation_depth,
        parent_ens_name=excluded.parent_ens_name;
    `);

    stmt.run(
      agent.ensName,
      agent.ownerAddress,
      agent.role,
      agent.status,
      agent.expiryTimestamp,
      agent.registeredAt,
      JSON.stringify(agent.textRecords),
      agent.isSimulated ? 1 : 0,
      agent.delegationDepth || 0,
      agent.parentEnsName || null
    );
  }

  public getAgent(ensName: string): AgentIdentity | null {
    const stmt = this.db.prepare(`SELECT * FROM agents WHERE ens_name = ?`);
    const row = stmt.get(ensName) as any;
    if (!row) return null;

    const textRecords = JSON.parse(row.text_records_json);
    let allowedCapabilities: string[] | undefined = undefined;
    if (textRecords["agent.capabilities"]) {
      try {
        allowedCapabilities = JSON.parse(textRecords["agent.capabilities"]);
      } catch {
        allowedCapabilities = [textRecords["agent.capabilities"]];
      }
    }

    return {
      ensName: row.ens_name,
      ownerAddress: row.owner_address,
      role: row.role,
      status: row.status,
      expiryTimestamp: Number(row.expiry_timestamp),
      registeredAt: Number(row.registered_at),
      textRecords,
      isSimulated: Boolean(row.is_simulated),
      delegationDepth: Number(row.delegation_depth),
      parentEnsName: row.parent_ens_name || undefined,
      allowedCapabilities
    };
  }

  public listAgents(): AgentIdentity[] {
    const stmt = this.db.prepare(`SELECT * FROM agents ORDER BY registered_at ASC`);
    const rows = stmt.all() as any[];
    return rows.map(row => {
      const textRecords = JSON.parse(row.text_records_json);
      let allowedCapabilities: string[] | undefined = undefined;
      if (textRecords["agent.capabilities"]) {
        try {
          allowedCapabilities = JSON.parse(textRecords["agent.capabilities"]);
        } catch {
          allowedCapabilities = [textRecords["agent.capabilities"]];
        }
      }

      return {
        ensName: row.ens_name,
        ownerAddress: row.owner_address,
        role: row.role,
        status: row.status,
        expiryTimestamp: Number(row.expiry_timestamp),
        registeredAt: Number(row.registered_at),
        textRecords,
        isSimulated: Boolean(row.is_simulated),
        delegationDepth: Number(row.delegation_depth),
        parentEnsName: row.parent_ens_name || undefined,
        allowedCapabilities
      };
    });
  }

  // --- Nonce Store ---
  public isNonceReplayed(nonce: string): boolean {
    const stmt = this.db.prepare(`SELECT 1 FROM nonces WHERE nonce = ?`);
    const row = stmt.get(nonce);
    return Boolean(row);
  }

  public recordNonce(nonce: string, tokenId: string, agentEnsName: string, timestamp: number): void {
    const stmt = this.db.prepare(`
      INSERT INTO nonces (nonce, token_id, agent_ens_name, timestamp)
      VALUES (?, ?, ?, ?)
    `);
    stmt.run(nonce, tokenId, agentEnsName, timestamp);
  }

  // --- Black Box Events & Hash Chain ---
  public getLatestEvent(): BlackBoxEvent | null {
    const stmt = this.db.prepare(`SELECT * FROM events ORDER BY sequence_number DESC LIMIT 1`);
    const row = stmt.get() as any;
    if (!row) return null;
    return this.mapEventRow(row);
  }

  public insertEvent(event: BlackBoxEvent): number {
    const stmt = this.db.prepare(`
      INSERT INTO events (
        event_id, prev_hash, hash, timestamp, agent_ens_name,
        approved_intent, policy_version, proposed_action_json,
        decision, reason_codes_json, human_approval_json,
        execution_result_json, payment_reference_json, hcs_anchor_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(
      event.eventId,
      event.prevHash,
      event.hash,
      event.timestamp,
      event.agentEnsName,
      event.approvedIntent,
      event.policyVersion,
      JSON.stringify(event.proposedAction),
      event.decision,
      JSON.stringify(event.reasonCodes),
      event.humanApproval ? JSON.stringify(event.humanApproval) : null,
      event.executionResult ? JSON.stringify(event.executionResult) : null,
      event.paymentReference ? JSON.stringify(event.paymentReference) : null,
      event.hcsAnchor ? JSON.stringify(event.hcsAnchor) : null
    );

    return Number(result.lastInsertRowid);
  }

  public updateEventHcsAnchor(eventId: string, hcsAnchor: NonNullable<BlackBoxEvent["hcsAnchor"]>): void {
    const stmt = this.db.prepare(`
      UPDATE events SET hcs_anchor_json = ? WHERE event_id = ?
    `);
    stmt.run(JSON.stringify(hcsAnchor), eventId);
  }

  public listEvents(limit: number = 100): BlackBoxEvent[] {
    const stmt = this.db.prepare(`
      SELECT * FROM events ORDER BY sequence_number ASC LIMIT ?
    `);
    const rows = stmt.all(limit) as any[];
    return rows.map(r => this.mapEventRow(r));
  }

  public getEventById(eventId: string): BlackBoxEvent | null {
    const stmt = this.db.prepare(`SELECT * FROM events WHERE event_id = ?`);
    const row = stmt.get(eventId) as any;
    if (!row) return null;
    return this.mapEventRow(row);
  }

  public manuallyTamperEvent(eventId: string, tamperedDecision: DecisionType): void {
    // Strictly for testing and tamper verification demonstrations
    const stmt = this.db.prepare(`UPDATE events SET decision = ? WHERE event_id = ?`);
    stmt.run(tamperedDecision, eventId);
  }

  private mapEventRow(row: any): BlackBoxEvent {
    return {
      eventId: row.event_id,
      sequenceNumber: Number(row.sequence_number),
      prevHash: row.prev_hash,
      hash: row.hash,
      timestamp: Number(row.timestamp),
      agentEnsName: row.agent_ens_name,
      approvedIntent: row.approved_intent,
      policyVersion: row.policy_version,
      proposedAction: JSON.parse(row.proposed_action_json),
      decision: row.decision as DecisionType,
      reasonCodes: JSON.parse(row.reason_codes_json) as ReasonCode[],
      humanApproval: row.human_approval_json ? JSON.parse(row.human_approval_json) : undefined,
      executionResult: row.execution_result_json ? JSON.parse(row.execution_result_json) : undefined,
      paymentReference: row.payment_reference_json ? JSON.parse(row.payment_reference_json) : undefined,
      hcsAnchor: row.hcs_anchor_json ? JSON.parse(row.hcs_anchor_json) : undefined
    };
  }

  // --- Incidents ---
  public insertIncident(incident: IncidentRecord): void {
    const stmt = this.db.prepare(`
      INSERT INTO incidents (
        incident_id, event_id, agent_ens_name, severity,
        reason_codes_json, description, detected_at, status,
        evidence_hash, hcs_anchor_json
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      incident.incidentId,
      incident.eventId,
      incident.agentEnsName,
      incident.severity,
      JSON.stringify(incident.reasonCodes),
      incident.description,
      incident.detectedAt,
      incident.status,
      incident.evidenceHash,
      incident.hcsAnchor ? JSON.stringify(incident.hcsAnchor) : null
    );
  }

  public listIncidents(): IncidentRecord[] {
    const stmt = this.db.prepare(`SELECT * FROM incidents ORDER BY detected_at DESC`);
    const rows = stmt.all() as any[];
    return rows.map(r => ({
      incidentId: r.incident_id,
      eventId: r.event_id,
      agentEnsName: r.agent_ens_name,
      severity: r.severity,
      reasonCodes: JSON.parse(r.reason_codes_json),
      description: r.description,
      detectedAt: Number(r.detected_at),
      status: r.status,
      evidenceHash: r.evidence_hash,
      hcsAnchor: r.hcs_anchor_json ? JSON.parse(r.hcs_anchor_json) : undefined
    }));
  }

  // --- Payment Authorization Tickets (Single-Use, Short-Lived) ---
  public issuePaymentTicket(
    ticketId: string,
    agentEnsName: string,
    actionId: string,
    destinationAccountId: string,
    amountTinybars: string,
    ttlSeconds: number = 300
  ): void {
    const now = Math.floor(Date.now() / 1000);
    const stmt = this.db.prepare(`
      INSERT INTO payment_tickets (
        ticket_id, agent_ens_name, action_id, destination_account_id,
        amount_tinybars, issued_at, expires_at, used
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 0)
    `);
    stmt.run(ticketId, agentEnsName, actionId, destinationAccountId, amountTinybars, now, now + ttlSeconds);
  }

  public consumePaymentTicket(ticketId: string, agentEnsName: string, amountTinybars: string, destinationAccountId: string): boolean {
    const now = Math.floor(Date.now() / 1000);
    const stmt = this.db.prepare(`
      SELECT * FROM payment_tickets 
      WHERE ticket_id = ? AND agent_ens_name = ? AND used = 0
    `);
    const row = stmt.get(ticketId, agentEnsName) as any;
    if (!row) return false;

    // Check expiration
    if (now > Number(row.expires_at)) {
      return false;
    }
    // Check parameters match exactly
    if (row.destination_account_id !== destinationAccountId || row.amount_tinybars !== amountTinybars) {
      return false;
    }

    // Mark as used atomically
    const updateStmt = this.db.prepare(`
      UPDATE payment_tickets SET used = 1 WHERE ticket_id = ? AND used = 0
    `);
    const result = updateStmt.run(ticketId);
    return result.changes > 0;
  }

  // --- Delegations ---
  public upsertDelegation(delegation: DelegationPassport): void {
    const stmt = this.db.prepare(`
      INSERT INTO delegations (
        child_ens_name, parent_ens_name, delegated_capabilities_json,
        depth, issued_at, expires_at, parent_signature, revoked
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(child_ens_name) DO UPDATE SET
        delegated_capabilities_json=excluded.delegated_capabilities_json,
        depth=excluded.depth,
        expires_at=excluded.expires_at,
        parent_signature=excluded.parent_signature,
        revoked=excluded.revoked;
    `);
    stmt.run(
      delegation.childEnsName,
      delegation.parentEnsName,
      JSON.stringify(delegation.delegatedCapabilities),
      delegation.depth,
      delegation.issuedAt,
      delegation.expiresAt,
      delegation.parentSignature,
      delegation.revoked ? 1 : 0
    );
  }

  public getDelegation(childEnsName: string): DelegationPassport | null {
    const stmt = this.db.prepare(`SELECT * FROM delegations WHERE child_ens_name = ?`);
    const row = stmt.get(childEnsName) as any;
    if (!row) return null;
    return {
      childEnsName: row.child_ens_name,
      parentEnsName: row.parent_ens_name,
      delegatedCapabilities: JSON.parse(row.delegated_capabilities_json),
      depth: Number(row.depth),
      issuedAt: Number(row.issued_at),
      expiresAt: Number(row.expires_at),
      parentSignature: row.parent_signature,
      revoked: Boolean(row.revoked)
    };
  }

  // --- HCS Anchors ---
  public recordHcsAnchor(
    topicId: string,
    sequenceNumber: number,
    consensusTimestamp: string,
    chainHeadHash: string,
    eventId: string,
    isSimulated: boolean = false
  ): void {
    const stmt = this.db.prepare(`
      INSERT INTO hcs_anchors (
        topic_id, sequence_number, consensus_timestamp,
        chain_head_hash, event_id, created_at, is_simulated
      ) VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      topicId,
      sequenceNumber,
      consensusTimestamp,
      chainHeadHash,
      eventId,
      Math.floor(Date.now() / 1000),
      isSimulated ? 1 : 0
    );
  }

  public listHcsAnchors(): any[] {
    const stmt = this.db.prepare(`SELECT * FROM hcs_anchors ORDER BY sequence_number DESC`);
    return stmt.all() as any[];
  }

  // Close database connection
  public close(): void {
    this.db.close();
  }
}
