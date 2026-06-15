import { ConfigPatch, MetricsSnapshot, Rule } from "../types/index.js";

/** Typed HTTP client for the waf-api REST endpoints. */
export class WafApiClient {
  constructor(private readonly baseUrl: string) {}

  async listRules(): Promise<Rule[]> {
    // TODO: GET /api/rules
    throw new Error("not implemented");
  }

  async upsertRule(rule: Rule): Promise<void> {
    // TODO: POST /api/rules
    throw new Error("not implemented");
  }

  async deleteRule(id: string): Promise<void> {
    // TODO: DELETE /api/rules/:id
    throw new Error("not implemented");
  }

  async getMetrics(): Promise<MetricsSnapshot> {
    // TODO: GET /api/metrics
    throw new Error("not implemented");
  }

  async updateConfig(patch: ConfigPatch): Promise<void> {
    // TODO: POST /api/config
    throw new Error("not implemented");
  }

  private async fetchJson<T>(path: string, init?: RequestInit): Promise<T> {
    // TODO: implement with fetch API; handle non-2xx as errors
    throw new Error("not implemented");
  }
}
