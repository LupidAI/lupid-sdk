/**
 * Unit tests for the OpenAI patch's prototype-location + install
 * verification (issue R25 / G19 — same SDK-restructuring class of bug as
 * the Anthropic patch G18b).
 *
 * `installOpenAIPatch` loads the module via `loadOptional("openai")`. We mock
 * that loader so we can feed deliberately-shaped fake modules where the
 * prototype the live `chat.completions` instance resolves through is NOT the
 * static `OpenAI.Chat.Completions.prototype`.
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

const PATCHED = Symbol.for("agentum.openai.patched");

function fakeEvaluatorThunk(): () => CedarToolCallClient | undefined {
  const client = {
    async evaluateToolCall() {
      return { decision: "allow", ttlMs: 0 } as const;
    },
  } as unknown as CedarToolCallClient;
  return () => client;
}

afterEach(async () => {
  try {
    await uninstallOpenAIPatch();
  } catch {
    /* ignore */
  }
  __nextModule = null;
});

/**
 * Fake `openai`-style module where the instance's `chat.completions`
 * prototype owns `create` on a base class up the chain and the static
 * `OpenAI.Chat.Completions` is a separate object identity.
 */
function makeNestedResourceModule(): {
  mod: Record<string, unknown>;
  instanceCreateOwner: object;
  staticCompletionsProto: object;
} {
  class BaseAPIResource {
    create(): Promise<unknown> {
      return Promise.resolve({ from: "base.create" });
    }
  }
  class LiveCompletions extends BaseAPIResource {}
  class StaticCompletions {
    create(): Promise<unknown> {
      return Promise.resolve({ from: "static.create" });
    }
  }

  class FakeOpenAI {
    chat: { completions: LiveCompletions };
    static Chat = { Completions: StaticCompletions };
    constructor(_opts: unknown) {
      this.chat = { completions: new LiveCompletions() };
    }
  }

  return {
    mod: { default: FakeOpenAI, OpenAI: FakeOpenAI },
    instanceCreateOwner: BaseAPIResource.prototype,
    staticCompletionsProto: StaticCompletions.prototype,
  };
}

describe("installOpenAIPatch — prototype location (R25/G19)", () => {
  it("patches the prototype the live instance resolves through, not the static export", async () => {
    const { mod, instanceCreateOwner, staticCompletionsProto } =
      makeNestedResourceModule();
    __nextModule = mod;

    const ok = await installOpenAIPatch(fakeEvaluatorThunk());
    expect(ok).toBe(true);

    expect(
      (instanceCreateOwner as Record<symbol, unknown>)[PATCHED],
    ).toBe(true);
    expect(
      (staticCompletionsProto as Record<symbol, unknown>)[PATCHED],
    ).toBeUndefined();

    const Ctor = mod["default"] as new (o: unknown) => {
      chat: { completions: { create: (...a: unknown[]) => unknown } };
    };
    const probe = new Ctor({ apiKey: "x" });
    expect(probe.chat.completions.create).toBe(
      (instanceCreateOwner as Record<string, unknown>)["create"],
    );
  });

  it("is idempotent — a second install does not re-wrap", async () => {
    const { mod, instanceCreateOwner } = makeNestedResourceModule();
    __nextModule = mod;

    expect(await installOpenAIPatch(fakeEvaluatorThunk())).toBe(true);
    const first = (instanceCreateOwner as Record<string, unknown>)["create"];
    expect(await installOpenAIPatch(fakeEvaluatorThunk())).toBe(true);
    expect((instanceCreateOwner as Record<string, unknown>)["create"]).toBe(
      first,
    );
  });
});

describe("installOpenAIPatch — install verification (R25)", () => {
  it("returns false (no false success) when the patch is unreachable from the instance", async () => {
    class FreshEveryTime {
      get chat(): { completions: { create: () => Promise<unknown> } } {
        return { completions: { create: () => Promise.resolve({}) } };
      }
    }
    __nextModule = { default: FreshEveryTime, OpenAI: FreshEveryTime };

    const ok = await installOpenAIPatch(fakeEvaluatorThunk());
    expect(ok).toBe(false);
  });

  it("returns false when no create method can be located at all", async () => {
    class NoChat {}
    __nextModule = { default: NoChat, OpenAI: NoChat };

    const ok = await installOpenAIPatch(fakeEvaluatorThunk());
    expect(ok).toBe(false);
  });
});
