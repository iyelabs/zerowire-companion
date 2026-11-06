export type OperationalEvent = {
  event: "public_request" | "scheduled_disabled" | "scheduled_not_implemented" | "scheduled_ingestion";
  request_id?: string;
  route?: "mcp" | "health" | "feed" | "unknown";
  status?: number;
  outcome?: "foundation_only" | "failed" | "disabled" | "success" | "skipped_locked";
  duration_ms?: number;
  count?: number;
};

/** Accept only fixed operational fields, never Request, headers, body, URL or IP. */
export function emitOperationalEvent(event: OperationalEvent): void {
  console.log(JSON.stringify(event));
}
