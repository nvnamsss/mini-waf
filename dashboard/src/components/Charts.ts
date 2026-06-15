import { MetricsSnapshot } from "../types/index.js";

/**
 * Renders attack-type distribution chart, top-attacker-IPs table,
 * and route heatmap from a MetricsSnapshot.
 */
export class ChartsComponent {
  /** Re-render all charts from fresh metrics data. */
  update(_metrics: MetricsSnapshot): void {
    // TODO: update bar chart (by_attack_type), table (top_ips), heatmap (route_heatmap)
    throw new Error("not implemented");
  }
}
