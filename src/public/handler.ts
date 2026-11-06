import type { WorkerEnv } from "../../cloudflare.config.ts";
import { emitOperationalEvent } from "../observability.ts";
import { handleMcp } from "./mcp.ts";
import { handleFeed } from "./feeds.ts";
import type { ReadQueries } from "./queries.ts";
import { consumeBoundedBody, PUBLIC_LIMITS, RequestLimitError } from "./limits.ts";

// Deliberately excludes DB and ingestion settings. This path has no source/write capability.
type PublicBindings = Pick<WorkerEnv, "PUBLIC_RATE_LIMITER"> & { queries: ReadQueries };

function reply(status: number, code: string, requestId: string, extraHeaders?: Record<string, string>): Response {
  const body = JSON.stringify({ status: code, request_id: requestId });
  if (new TextEncoder().encode(body).byteLength > PUBLIC_LIMITS.responseBytes) {
    throw new Error("Response exceeds public response limit");
  }
  return new Response(body, {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "x-request-id": requestId,
      ...extraHeaders,
    },
  });
}

async function boundedMcpResponse(response: Response, requestId: string): Promise<Response> {
  if (!response.body) return response;
  const reader = response.body.getReader(); const chunks: Uint8Array[] = []; let size = 0;
  try {
    while (true) { const part = await reader.read(); if (part.done) break; size += part.value.byteLength; if (size > PUBLIC_LIMITS.responseBytes) throw new Error("response_too_large"); chunks.push(part.value); }
  } catch (error) { await reader.cancel().catch(() => undefined); throw error; }
  finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  const headers = new Headers(response.headers); headers.set("cache-control","no-store"); headers.set("x-content-type-options","nosniff"); headers.set("content-security-policy","default-src 'none'; frame-ancestors 'none'"); headers.set("x-request-id",requestId); headers.delete("content-length");
  return new Response(bytes, {status:response.status,headers});
}

async function limiterKey(request: Request): Promise<string> {
  // At the Cloudflare edge this header is platform-managed. Never log it or the hash.
  const identity = request.headers.get("cf-connecting-ip") ?? "unidentified-local-client";
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(identity));
  return `mcp:${Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("")}`;
}

export async function handlePublicRequest(request: Request, bindings: PublicBindings): Promise<Response> {
  const requestId = crypto.randomUUID();
  const started = performance.now();
  let route: "mcp" | "health" | "feed" | "unknown" = "unknown";
  let response: Response;
  try {
    const url = new URL(request.url);
    route = url.pathname === "/mcp" ? "mcp" : url.pathname === "/health" && request.method === "GET" ? "health" : url.pathname === "/events.json" || url.pathname === "/events.xml" ? "feed" : "unknown";
    // Apply the same fail-closed limiter to every path, including probes and
    // unknown URLs. This controls per-client abuse, not total account spend.
    const decision = await bindings.PUBLIC_RATE_LIMITER.limit({ key: await limiterKey(request) });
    if (!decision.success) {
      response = reply(429, "rate_limited", requestId, { "retry-after": "60" });
    } else if (request.url.length > PUBLIC_LIMITS.urlCharacters) {
      response = reply(414, "url_too_long", requestId);
    } else if (url.pathname === "/health" && request.method === "GET") {
      route = "health";
      // Liveness only. Does not assert source freshness, D1 readiness or MCP availability.
      response = reply(200, "ok", requestId);
    } else if (url.pathname === "/events.json" || url.pathname === "/events.xml") {
      response = await boundedMcpResponse(await handleFeed(request,bindings.queries),requestId);
    } else if (url.pathname !== "/mcp") {
      response = reply(404, "not_found", requestId);
    } else {
      route = "mcp";
      if (request.headers.has("origin") && request.headers.get("origin") !== url.origin) {
        response = reply(403, "origin_not_allowed", requestId);
      } else if (request.method !== "POST") {
        response = reply(405, "method_not_allowed", requestId, { allow: "POST" });
      } else if (request.headers.has("content-encoding") && request.headers.get("content-encoding") !== "identity") {
        response = reply(415, "content_encoding_not_supported", requestId);
      } else if (request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() !== "application/json") {
        response = reply(415, "expected_application_json", requestId);
      } else {
        await consumeBoundedBody(request.clone());
        response = await boundedMcpResponse(await handleMcp(request, bindings.queries), requestId);
      }
    }
  } catch (error) {
    response = error instanceof RequestLimitError
      ? reply(error.status, error.code, requestId)
      : reply(503, "public_service_unavailable", requestId);
  }
  emitOperationalEvent({
    event: "public_request", request_id: requestId, route,
    status: response.status, duration_ms: Math.round(performance.now() - started),
  });
  return response;
}
