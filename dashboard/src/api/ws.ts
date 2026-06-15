import { AuditEntry } from "../types/index.js";

/** Subscribe to the live WAF audit feed over WebSocket. */
export class WafFeedClient {
  private ws: WebSocket | null = null;

  constructor(private readonly wsUrl: string) {}

  /**
   * Connect and call `onEntry` for each inbound AuditEntry.
   * Reconnects automatically on disconnect.
   */
  connect(onEntry: (entry: AuditEntry) => void): void {
    // TODO: open WebSocket to wsUrl; on message parse JSON and call onEntry;
    //        on close schedule reconnect with exponential back-off
    throw new Error("not implemented");
  }

  disconnect(): void {
    // TODO: close WebSocket cleanly
    throw new Error("not implemented");
  }
}
