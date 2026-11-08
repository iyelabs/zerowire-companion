import type { WorkerEnv } from "../cloudflare.config.ts";
import { handleScheduledIngestion } from "./ingestion/scheduled.ts";
import { createQueries } from "./public/queries.ts";
import { handlePublicRequest } from "./public/handler.ts";

export default {
  async fetch(request, env): Promise<Response> {
    // No DB/source/scheduled capability crosses into the public request handler.
    return handlePublicRequest(request, { PUBLIC_RATE_LIMITER: env.PUBLIC_RATE_LIMITER, queries: createQueries(env.DB) });
  },
  async scheduled(_controller, env): Promise<void> {
    await handleScheduledIngestion(env);
  },
} satisfies ExportedHandler<WorkerEnv & { GITHUB_ADVISORY_TOKEN?:string }>;
