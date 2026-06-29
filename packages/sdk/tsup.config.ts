import { defineConfig } from "tsup";

export default defineConfig({
  entry: {
    index: "src/index.ts",
    "frameworks/langchain": "src/frameworks/langchain.ts",
    "frameworks/vercel-ai": "src/frameworks/vercel-ai.ts",
    "frameworks/openai": "src/frameworks/openai.ts",
    "frameworks/express": "src/frameworks/express/index.ts",
    lite: "src/lite.ts",
    "frameworks/nextjs": "src/frameworks/nextjs/index.ts",
    "frameworks/fastify": "src/frameworks/fastify/index.ts",
    "frameworks/nestjs": "src/frameworks/nestjs/index.ts",
    init: "src/init.ts",
    "instrumentation/openai-patch":    "src/instrumentation/openai-patch.ts",
    "instrumentation/anthropic-patch": "src/instrumentation/anthropic-patch.ts",
    "evaluation/cedar-client":         "src/evaluation/cedar-client.ts",
    pii:                               "src/pii/index.ts",
  },
  format: ["cjs", "esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  splitting: false,
  treeshake: true,
  external: ["@langchain/core", "ai", "openai", "@anthropic-ai/sdk"],
});
