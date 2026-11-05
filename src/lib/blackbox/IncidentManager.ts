/**
 * MORTAL 2.0 — Incident Manager
 * Tracks policy violations, creates audit incident files,
 * and coordinates cryptographic evidence anchoring.
 */

import { randomUUID } from "node:crypto";
import type { IncidentRecord, ReasonCode } from "../../types/index.ts";
import { DatabaseService } from "../db/database.ts";

export interface CreateIncidentParams {
  eventId: string;
  agentEnsName: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  reasonCodes: ReasonCode[];
  description: string;
  evidenceHash: string;
}

export class IncidentManager {
  private db: DatabaseService;

  constructor(db: DatabaseService) {
    this.db = db;
  }

  /**
   * Creates and persists an incident record upon policy violation.
   */
  public createIncident(params: CreateIncidentParams): IncidentRecord {
    const incidentId = "inc_" + randomUUID();
    const now = Math.floor(Date.now() / 1000);

    const incident: IncidentRecord = {
      incidentId,
      eventId: params.eventId,
      agentEnsName: params.agentEnsName,
      severity: params.severity,
      reasonCodes: params.reasonCodes,
      description: params.description,
      detectedAt: now,
      status: "OPEN",
      evidenceHash: params.evidenceHash
    };

    this.db.insertIncident(incident);
    return incident;
  }

  public listIncidents(): IncidentRecord[] {
    return this.db.listIncidents();
  }
}
