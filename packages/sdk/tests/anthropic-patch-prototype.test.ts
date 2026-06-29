/**
 * Unit tests for the Anthropic patch's prototype-location + install
 * verification (issue R25 / G18b).
 *
 * The bug: `locateMessagesPrototype` resolved a prototype via the static
 * export tree that is NOT the one a freshly constructed
 * `new Anthropic().messages` instance method-resolves through in
 * `@anthropic-ai/sdk` ≥0.30 (incl. 0.73.x). `installAnthropicPatch` returned
 * `true` and stamped the marker on the wrong object — the patch was dead
 * while reporting success.
 *
 * The fix: walk the live instance prototype chain to the object with an
 * **own** `create` property and patch THAT; then verify a fresh probe
 * resolves the patched function, returning `false` if not.
 *
 * `installAnthropicPatch` loads the module via `loadOptional("@anthropic-ai/sdk")`.
 * We mock that loader so we can feed deliberately-shaped fake modules without
 * an installed peer dependency.
 */

import type { CedarToolCallClient } from "../src/evaluation/cedar-client";

// Mock the optional loader so we control exactly what module shape the patch
// sees. Each test sets `__nextModule` before calling install/uninstall.
let __nextModule: unknown = null;
jest.mock("../src/instrumentation/_optional", () => ({
  loadOptional: async () => __nextModule,
}));

import {
  installAnthropicPatch,
  uninstallAnthropicPatch,
} from "../src/instrumentation/anthropic-patch";

const PATCHED = Symbol.for("agentum.anthropic.patched");

function fakeEvaluatorThunk(): () => CedarToolCallClient | undefined {
  const client = {
    async evaluateToolCall() {
      return { decision: "allow", ttlMs: 0 } as const;
    },
  } as unknown as CedarToolCallClient;
  return () => client;
}

afterEach(async () => {
  // Best-effort cleanup so markers don't leak between tests.
  try {
    await uninstallAnthropicPatch();
  } catch {
    /* ignore */
  }
  __nextModule = null;
});

/**
 * Build a fake `@anthropic-ai/sdk@0.73`-style module where the prototype the
 * INSTANCE uses for `messages` is NOT the same object as the static
 * `Anthropic.Messages.prototype`, and `create` lives on a base class up the
 * chain (own property on the base, inherited by the concrete resource).
 */
function makeNestedResourceModule(): {
  mod: Record<string, unknown>;
  instanceCreateOwner: object;
  staticMessagesProto: object;
} {
  // Base resource class that owns `create`.
  class BaseResource {
    create(): Promise<unknown> {
      return Promise.resolve({ from: "base.create" });
    }
  }
  // The concrete class the live instance uses — inherits create, does NOT
  // own it.
  class LiveMessages extends BaseResource {}
  // A *different* class exposed as the static export — same-named but a
  // separate object identity, mimicking the export/instance divergence.
  class StaticMessages {
    create(): Promise<unknown> {
      return Promise.resolve({ from: "static.create" });
    }
  }

  class FakeAnthropic {
    messages: LiveMessages;
    static Messages = StaticMessages;
    constructor(_opts: unknown) {
      this.messages = new LiveMessages();
    }
  }

  return {
    mod: { default: FakeAnthropic, Anthropic: FakeAnthropic },
    instanceCreateOwner: BaseResource.prototype,
    staticMessagesProto: StaticMessages.prototype,
  };
}

describe("installAnthropicPatch — prototype location (R25/G18b)", () => {
  it("patches the prototype the live instance resolves through, not the static export", async () => {
    const { mod, instanceCreateOwner, staticMessagesProto } =
      makeNestedResourceModule();
    __nextModule = mod;

    const ok = await installAnthropicPatch(fakeEvaluatorThunk());
    expect(ok).toBe(true);

    // The own-create owner the instance uses is patched.
    const ownerDesc = Object.getOwnPropertyDescriptor(
      instanceCreateOwner,
      "create",
    );
    expect(ownerDesc).toBeDefined();
    expect(
      (instanceCreateOwner as Record<symbol, unknown>)[PATCHED],
    ).toBe(true);

    // The static export prototype is left untouched (no false patch).
    expect(
      (staticMessagesProto as Record<symbol, unknown>)[PATCHED],
    ).toBeUndefined();

    // A freshly constructed instance resolves the patched function.
    const Ctor = mod["default"] as new (o: unknown) => {
      messages: { create: (...a: unknown[]) => unknown };
    };
    const probe = new Ctor({ apiKey: "x" });
    expect((probe.messages.create as { name?: string }).name).toBe("create");
    // The patched function is reachable from the instance call path: it is
    // the very function installed on the own-create owner.
    expect(probe.messages.create).toBe(
      (instanceCreateOwner as Record<string, unknown>)["create"],
    );
  });

  it("is idempotent — a second install does not re-wrap", async () => {
    const { mod, instanceCreateOwner } = makeNestedResourceModule();
    __nextModule = mod;

    expect(await installAnthropicPatch(fakeEvaluatorThunk())).toBe(true);
    const first = (instanceCreateOwner as Record<string, unknown>)["create"];
    expect(await installAnthropicPatch(fakeEvaluatorThunk())).toBe(true);
    const second = (instanceCreateOwner as Record<string, unknown>)["create"];
    expect(second).toBe(first);
  });
});

describe("installAnthropicPatch — install verification (R25)", () => {
  it("returns false (no false success) when the patch is unreachable from the instance", async () => {
    // Weird export shape: the constructor's `messages` is a getter that
    // returns a brand-new object on every access whose `create` is an own
    // property — so patching the prototype we located never affects the
    // function the next probe resolves. Verification must catch this and
    // return false.
    class FreshEveryTime {
      get messages(): { create: () => Promise<unknown> } {
        // New object literal each access; `create` is own on the literal,
        // never inherited from a shared prototype.
        return {
          create: () => Promise.resolve({}),
        };
      }
    }
    const mod: Record<string, unknown> = {
      default: FreshEveryTime,
      Anthropic: FreshEveryTime,
    };
    __nextModule = mod;

    const ok = await installAnthropicPatch(fakeEvaluatorThunk());
    expect(ok).toBe(false);
  });

  it("returns false when no create method can be located at all", async () => {
    class NoMessages {
      // no messages property
    }
    __nextModule = { default: NoMessages, Anthropic: NoMessages };

    const ok = await installAnthropicPatch(fakeEvaluatorThunk());
    expect(ok).toBe(false);
  });

  it("returns false when the module is absent", async () => {
    __nextModule = null;
    const ok = await installAnthropicPatch(fakeEvaluatorThunk());
    expect(ok).toBe(false);
  });
});
