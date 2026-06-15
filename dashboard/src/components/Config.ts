import { WafApiClient } from "../api/client.js";
import { ConfigPatch, Rule } from "../types/index.js";

/**
 * Hot-config panel: displays current rules and thresholds, allows
 * updating them in real time without restarting the WAF.
 */
export class ConfigComponent {
  constructor(private readonly api: WafApiClient) {}

  /** Load and render the current rule list. */
  async loadRules(): Promise<void> {
    // TODO: call api.listRules(); render editable rule table
    throw new Error("not implemented");
  }

  /** Save a modified rule back to the WAF. */
  async saveRule(_rule: Rule): Promise<void> {
    // TODO: call api.upsertRule(rule); refresh table row
    throw new Error("not implemented");
  }

  /** Delete a rule from the WAF. */
  async deleteRule(_id: string): Promise<void> {
    // TODO: call api.deleteRule(id); remove table row
    throw new Error("not implemented");
  }

  /** Apply threshold / rate-limit changes. */
  async applyConfigPatch(_patch: ConfigPatch): Promise<void> {
    // TODO: call api.updateConfig(patch); show success toast
    throw new Error("not implemented");
  }
}
