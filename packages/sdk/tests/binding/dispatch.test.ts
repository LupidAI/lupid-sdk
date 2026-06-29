/**
 * Unit tests for the S2-E04 per-mode init scan dispatcher.
 *
 * Covers `extractBindingMode` (raw YAML → mode | null | throw) and
 * `runPerModeScan` (mode → proceed | warn+default | throw). Init-level
 * integration is covered in `tests/binding/init-binding-mode.test.ts`.
 */

import {
  ALL_BINDING_MODES,
  ACTIVE_BINDING_MODES,
  DEFERRED_BINDING_MODES,
  MVP3_REFERENCE_TICKETS,
  BindingModeNotYetSupportedError,
  InvalidBindingModeError,
  extractBindingMode,
  runPerModeScan,
  type BindingMode,
} from "../../src/binding";

function silentLogger(): {
  log: jest.Mock;
  warn: jest.Mock;
  error: jest.Mock;
} {
  return { log: jest.fn(), warn: jest.fn(), error: jest.fn() };
}

describe("extractBindingMode", () => {
  it("returns null when the raw value is not an object", () => {
    expect(extractBindingMode(null)).toBeNull();
    expect(extractBindingMode(undefined)).toBeNull();
    expect(extractBindingMode("string")).toBeNull();
    expect(extractBindingMode(42)).toBeNull();
  });

  it("returns null when spec or spec.runtime is missing", () => {
    expect(extractBindingMode({})).toBeNull();
    expect(extractBindingMode({ spec: null })).toBeNull();
    expect(extractBindingMode({ spec: {} })).toBeNull();
    expect(extractBindingMode({ spec: { runtime: null } })).toBeNull();
    expect(extractBindingMode({ spec: { runtime: {} } })).toBeNull();
  });

  it("returns null when binding_mode is absent", () => {
    expect(
      extractBindingMode({
        spec: { runtime: { language: "typescript" } },
      }),
    ).toBeNull();
  });

  it.each(ALL_BINDING_MODES)("accepts %s", (mode) => {
    expect(
      extractBindingMode({
        spec: { runtime: { binding_mode: mode } },
      }),
    ).toBe(mode);
  });

  it("throws InvalidBindingModeError on unknown string value", () => {
    expect(() =>
      extractBindingMode({
        spec: { runtime: { binding_mode: "made_up_mode" } },
      }),
    ).toThrow(InvalidBindingModeError);
  });

  it("throws InvalidBindingModeError on non-string value", () => {
    expect(() =>
      extractBindingMode({
        spec: { runtime: { binding_mode: 42 } },
      }),
    ).toThrow(InvalidBindingModeError);
  });

  it("surfaces the bad value on the error so operators can locate it", () => {
    try {
      extractBindingMode({
        spec: { runtime: { binding_mode: "typo_mode" } },
      });
      fail("expected throw");
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidBindingModeError);
      expect((err as InvalidBindingModeError).received).toBe("typo_mode");
    }
  });
});

describe("runPerModeScan", () => {
  describe.each(ACTIVE_BINDING_MODES)("active mode %s", (mode) => {
    it("proceeds without throwing", () => {
      const logger = silentLogger();
      const out = runPerModeScan(mode, logger);
      expect(out.bindingMode).toBe(mode);
      expect(out.defaulted).toBe(false);
      expect(logger.warn).not.toHaveBeenCalled();
    });
  });

  describe.each(DEFERRED_BINDING_MODES)("deferred mode %s", (mode) => {
    it("throws BindingModeNotYetSupportedError", () => {
      const logger = silentLogger();
      expect(() => runPerModeScan(mode, logger)).toThrow(
        BindingModeNotYetSupportedError,
      );
    });

    it("error carries mode, supportedAt, referenceTickets", () => {
      const logger = silentLogger();
      try {
        runPerModeScan(mode, logger);
        fail("expected throw");
      } catch (err) {
        expect(err).toBeInstanceOf(BindingModeNotYetSupportedError);
        const e = err as BindingModeNotYetSupportedError;
        expect(e.mode).toBe(mode);
        expect(e.supportedAt).toBe("MVP-3");
        expect(e.referenceTickets).toEqual(MVP3_REFERENCE_TICKETS);
        expect(e.referenceTickets).toContain("S2-H01");
        expect(e.referenceTickets).toContain("S2-H09");
        // Message must point at the ticket series so the user knows
        // where to track the work.
        expect(e.message).toContain("MVP-3");
        expect(e.message).toContain("S2-H01");
        expect(e.message).toContain(mode);
      }
    });
  });

  it("defaults null (no binding_mode declared) to orchestrator with a warning", () => {
    const logger = silentLogger();
    const out = runPerModeScan(null, logger);
    expect(out.bindingMode).toBe("orchestrator");
    expect(out.defaulted).toBe(true);
    expect(logger.warn).toHaveBeenCalledTimes(1);
    const warning = String(logger.warn.mock.calls[0]?.[0]);
    expect(warning).toMatch(/binding_mode/);
    expect(warning).toMatch(/orchestrator/);
  });
});

describe("compile-time constants", () => {
  it("ALL_BINDING_MODES enumerates all five modes", () => {
    expect(ALL_BINDING_MODES).toHaveLength(5);
    // The literal-typed array means TS catches additions; this runtime
    // assertion catches deletions / reorderings.
    expect(new Set(ALL_BINDING_MODES)).toEqual(
      new Set<BindingMode>([
        "orchestrator",
        "per_subagent",
        "acl_edge",
        "actor_per_instance",
        "framework_hook",
      ]),
    );
  });

  it("ACTIVE + DEFERRED partition ALL_BINDING_MODES", () => {
    expect(new Set([...ACTIVE_BINDING_MODES, ...DEFERRED_BINDING_MODES])).toEqual(
      new Set(ALL_BINDING_MODES),
    );
    expect(ACTIVE_BINDING_MODES.length + DEFERRED_BINDING_MODES.length).toBe(
      ALL_BINDING_MODES.length,
    );
  });

  it("MVP3_REFERENCE_TICKETS covers S2-H01..S2-H09", () => {
    expect(MVP3_REFERENCE_TICKETS).toHaveLength(9);
    for (let i = 1; i <= 9; i++) {
      expect(MVP3_REFERENCE_TICKETS).toContain(
        `S2-H0${i.toString()}`,
      );
    }
  });
});
