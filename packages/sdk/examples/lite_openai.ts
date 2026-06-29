/**
 * Agentum SDK-Lite + OpenAI — governed Node.js agent.
 *
 * Run:
 *   npx tsx examples/lite_openai.ts
 */

import { init } from "@lupid/sdk/lite";
import OpenAI from "openai";

async function main() {
  // Initialize governance — sets HTTPS_PROXY and NODE_EXTRA_CA_CERTS.
  await init({
    gateway: "http://localhost:7071",
    apiKey: "your-operator-key",
    name: "openai-node-bot",
    purpose: "Research assistant",
  });

  // OpenAI client respects HTTPS_PROXY env var automatically.
  const openai = new OpenAI();
  const response = await openai.chat.completions.create({
    model: "gpt-4",
    messages: [
      { role: "user", content: "Summarize recent advances in AI safety." },
    ],
  });

  console.log(response.choices[0].message.content);
}

main().catch(console.error);
