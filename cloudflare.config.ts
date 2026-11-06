import { bindings, defineConfig, triggers, type InferEnv, type UnwrapConfig } from "cf/config";

const config = defineConfig({
  worker: {
    name: "zerowire-companion",
    entrypoint: "./src/index.ts",
    compatibilityDate: "2026-11-04",
    compatibilityFlags: ["nodejs_compat"],
    workersDev: true,
    previewUrls: false,
    env: {
      DB: bindings.d1({ name: "zerowire-companion-intelligence" }),
      PUBLIC_RATE_LIMITER: bindings.rateLimit({
        namespace: "2261104",
        simple: { limit: 60, period: 60 },
      }),
      INGESTION_ENABLED: bindings.text("false"),
    },
    triggers: [triggers.scheduled({ schedule: "0 * * * *" })],
    limits: { cpuMs: 50 },
    observability: {
      enabled: true,
      redactQueryString: true,
      logs: { enabled: true, invocationLogs: false, headSamplingRate: 1 },
      traces: { enabled: true, headSamplingRate: 0.01 },
    },
  },
});

export type WorkerEnv = InferEnv<UnwrapConfig<typeof config.worker>>;
export default config;
