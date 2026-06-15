import { AuditEntry } from "../types/index.js";

/**
 * Renders the live request log table.
 * Each row shows: timestamp, IP, method, path, tier, risk score, action, rule.
 */
export class FeedComponent {
  private entries: AuditEntry[] = [];

  /** Append a new entry and re-render the visible rows. */
  push(entry: AuditEntry): void {
    // TODO: prepend to entries array; cap list at MAX_ROWS; update DOM table
    throw new Error("not implemented");
  }

  /** Clear all displayed entries. */
  clear(): void {
    // TODO: reset entries array; clear table DOM element
    throw new Error("not implemented");
  }
}
