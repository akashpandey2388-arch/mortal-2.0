/**
 * MORTAL 2.0 — Sentinel Capability Manager
 * Enforces allowed tools and accessible resources per policy.
 */

import type { ActionProposal, ReasonCode } from "../../types/index.ts";
import { DEFAULT_POLICY, type PolicyConfig } from "../../../config/policy.ts";

export interface CapabilityCheckResult {
  passed: boolean;
  reasonCode?: ReasonCode;
  error?: string;
}

export class CapabilityManager {
  private policy: PolicyConfig;

  constructor(policy: PolicyConfig = DEFAULT_POLICY) {
    this.policy = policy;
  }

  /**
   * Verifies that the requested tool is explicitly permitted by policy.
   */
  public checkTool(tool: string): CapabilityCheckResult {
    const isAllowed = this.policy.allowedTools.includes(tool);
    if (!isAllowed) {
      return {
        passed: false,
        reasonCode: "TOOL_NOT_PERMITTED",
        error: `Tool "${tool}" is not in policy allowed tools list: [${this.policy.allowedTools.join(", ")}]`
      };
    }
    return { passed: true };
  }

  /**
   * Verifies that the targeted resource conforms to allowed URI patterns.
   */
  public checkResource(resource: string): CapabilityCheckResult {
    const isAllowed = this.policy.allowedResources.some(pattern => {
      if (pattern.endsWith("/*")) {
        const prefix = pattern.slice(0, -2);
        return resource.startsWith(prefix);
      }
      return resource === pattern;
    });

    if (!isAllowed) {
      return {
        passed: false,
        reasonCode: "RESOURCE_NOT_PERMITTED",
        error: `Target resource "${resource}" does not match permitted policy resources: [${this.policy.allowedResources.join(", ")}]`
      };
    }

    return { passed: true };
  }
}
