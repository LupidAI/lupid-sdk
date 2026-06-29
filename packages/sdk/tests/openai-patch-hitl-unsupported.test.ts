/**
 * HITL-8 — Autopatch HITL honesty, driven through the real OpenAI patch.
 *
 * Installs `installOpenAIPatch` with an evaluator that returns a
 * `require_hitl` DENY, then invokes the patched `create()` twice. Asserts:
 *   - `console.warn` fires exactly ONCE across the two identical calls
 *     (dedup), naming the gap and the supported alternatives;
 *   - the deny STANDS — the denied tool_call is dropped from the response
 *     and `finish_reason` is rewritten to `"stop"` (no retry, no re-invoke);
 *   - the call resolves (never hangs) and the original `create` is invoked
 *     once per call (no auto-retry to the LLM).
 */

import type { CedarToolCallClient } from "../src/evaluation/cedar-client";

let __nextModule: unknown = null;
jest.mock("../src/instrumentation/_optional", () => ({
  loadOptional: async () => __nextModule,
}));

import {
  installOpenAIPatch,
  uninstallOpenAIPatch,
} from "../src/instrumentation/openai-patch";
import { __resetHitlUnsupportedWarnings } from "../src/instrumentation/hitl-unsupported";

/** Tool-call response the fake LLM returns on every `create()`. */
function toolCallResponse(): Record<string, unknown> {
  return {
    choices: [
      {
        index: 0,
        finish_reason: "tool_calls",
        message: {
          role: "assistant",
          content: "",
          tool_calls: [
            {
              id: "call_1",
              type: "function",
              function: { name: "wire_money", arguments: '{"amount":100}' },
            },
          ],
        },
      },
    ],
  };
}

/**
 * Fake `openai` module whose `create` records each invocation and returns a
 * fresh tool-call response. `createCalls` lets us prove there is no auto-retry.
 */
function makeModule(): {
  mod: Record<string, unknown>;
  createCalls: () => number;
  ctor: new (opts: unknown) => { chat: { completions: { create: () => Promise<unknown> } } };
} {
  let calls = 0;
  class Completions {
    create(): Promise<unknown> {
      calls += 1;
      return Promise.resolve(toolCallResponse());
    }
  }
  class FakeOpenAI {
    chat: { completions: Completions };
    static Chat = { Completions };
    constructor(_opts: unknown) {
      this.chat = { completions: new Completions() };
    }
  }
  return {
    mod: { default: FakeOpenAI, OpenAI: FakeOpenAI },
    createCalls: () => calls,
    ctor: FakeOpenAI as unknown as new (opts: unknown) => {
      chat: { completions: { create: () => Promise<unknown> } };
    },
  };
}

/** Evaluator that always returns a `require_hitl` deny. */
function hitlDenyEvaluatorThunk(): () => CedarToolCallClient {
  const client = {
    async evaluateToolCall() {
      return { decision: "deny", ttlMs: 0, reason: "needs approval", advice: ["require_hitl"] } as const;
    },
  } as unknown as CedarToolCallClient;
  return () => client;
}

let warnSpy: jest.SpyInstance;

beforeEach(() => {
  __resetHitlUnsupportedWarnings();
  warnSpy = jest.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(async () => {
  try {
    await uninstallOpenAIPatch();
  } catch {
    /* ignore */
  }
  warnSpy.mockRestore();
  __nextModule = null;
});

describe("OpenAI patch — HITL-8 unsupported-plane honesty", () => {
  it("warns once across two identical require_hitl denies, drops the tool call, never retries", async () => {
    const m = makeModule();
    __nextModule = m.mod;
    expect(await installOpenAIPatch(hitlDenyEvaluatorThunk())).toBe(true);

    const client = new m.ctor({ apiKey: "test" });

    // First call → require_hitl deny.
    const r1 = (await client.chat.completions.create()) as Record<string, unknown>;
    // Second identical call → same deny.
    const r2 = (await client.chat.completions.create()) as Record<string, unknown>;

    // Warn fired exactly once (dedup), with the gap message + alternatives.
    const hitlWarns = warnSpy.mock.calls
      .map((c) => String(c[0]))
      .filter((s) => s.includes("autopatch HITL unsupported in v1"));
    expect(hitlWarns).toHaveLength(1);
    expect(hitlWarns[0]).toContain("Express/Fastify/NestJS");
    expect(hitlWarns[0]).toContain("R22");

    // Deny STANDS: the denied tool_call is dropped and finish_reason rewritten.
    for (const r of [r1, r2]) {
      const choice = (r["choices"] as Array<Record<string, unknown>>)[0]!;
      const message = choice["message"] as Record<string, unknown>;
      expect(message["tool_calls"]).toBeUndefined();
      expect(choice["finish_reason"]).toBe("stop");
      expect(String(message["content"])).toContain("wire_money");
    }

    // No auto-retry / re-invoke: exactly one upstream `create` per call.
    expect(m.createCalls()).toBe(2);
  });
});
