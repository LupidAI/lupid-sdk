/**
 * S1-12 — version-negotiation reconciler.
 *
 * 6-case table:
 *   1. both null              → throw `InitError`
 *   2. only local present     → return local (warn)
 *   3. only live present      → return live  (warn)
 *   4. equal versions         → return local (no warn)
 *   5. local > live           → return live  (warn)
 *   6. local < live           → throw `InitError`
 */

import { reconcileVersions } from "../../src/manifest/reconcile";
import { InitError } from "../../src/manifest/errors";
import type { TenantSchema } from "../../src/manifest/types";

function mkSchema(version: number): TenantSchema {
  return { version, dimensions: [] };
}

function silentLogger(): { warn: jest.Mock } {
  return { warn: jest.fn() };
}

describe("reconcileVersions", () => {
  it("throws InitError when both local and live are null", () => {
    const log = silentLogger();
    expect(() => reconcileVersions(null, null, log)).toThrow(InitError);
  });

  it("returns local with a warning when live is null", () => {
    const log = silentLogger();
    const local = mkSchema(3);
    expect(reconcileVersions(local, null, log)).toBe(local);
    expect(log.warn).toHaveBeenCalled();
  });

  it("returns live with a warning when local is null", () => {
    const log = silentLogger();
    const live = mkSchema(4);
    expect(reconcileVersions(null, live, log)).toBe(live);
    expect(log.warn).toHaveBeenCalled();
  });

  it("returns local when versions are equal without warning", () => {
    const log = silentLogger();
    const local = mkSchema(5);
    const live = mkSchema(5);
    expect(reconcileVersions(local, live, log)).toBe(local);
    expect(log.warn).not.toHaveBeenCalled();
  });

  it("returns live with a warning when local > live", () => {
    const log = silentLogger();
    const local = mkSchema(7);
    const live = mkSchema(5);
    expect(reconcileVersions(local, live, log)).toBe(live);
    expect(log.warn).toHaveBeenCalled();
  });

  it("throws InitError when local < live", () => {
    const log = silentLogger();
    const local = mkSchema(2);
    const live = mkSchema(4);
    expect(() => reconcileVersions(local, live, log)).toThrow(InitError);
  });
});
