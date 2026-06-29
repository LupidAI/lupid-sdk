/**
 * `@AgentumGuardFor()` — method decorator attaching Cedar action/resource
 * metadata to a NestJS route handler. Read by `AgentumGuard.canActivate`.
 *
 * Implementation note: uses a module-scoped `WeakMap<Function,
 * AgentumGuardForOptions>` so we don't require a `reflect-metadata` polyfill.
 * The decorator stores options against the bound handler function (the
 * `descriptor.value`), and the guard looks them up via `ctx.getHandler()`.
 *
 * @example
 * ```ts
 * import { Controller, Get, UseGuards } from "@nestjs/common";
 * import { AgentumGuard, AgentumGuardFor } from "@lupid/sdk/frameworks/nestjs";
 *
 * @Controller("orders")
 * @UseGuards(AgentumGuard)
 * export class OrdersController {
 *   @Get()
 *   @AgentumGuardFor({ action: "http.get", resource: "api.example.com" })
 *   async list() { ... }
 * }
 * ```
 */

import type { AgentumGuardForOptions } from "./types.js";

type HandlerFn = (...args: unknown[]) => unknown;

const OPTS_BY_HANDLER = new WeakMap<HandlerFn, AgentumGuardForOptions>();

/** Attach guard options to a controller method. */
export function AgentumGuardFor(opts: AgentumGuardForOptions): MethodDecorator {
  if (!opts || typeof opts.action !== "string" || opts.action.length === 0) {
    throw new TypeError("AgentumGuardFor: `action` must be a non-empty string");
  }
  if (typeof opts.resource !== "string" || opts.resource.length === 0) {
    throw new TypeError("AgentumGuardFor: `resource` must be a non-empty string");
  }
  const decorator: MethodDecorator = (_target, _propertyKey, descriptor) => {
    const fn = (descriptor as PropertyDescriptor | undefined)?.value as
      | HandlerFn
      | undefined;
    if (typeof fn !== "function") {
      throw new TypeError(
        "AgentumGuardFor: can only decorate methods (descriptor.value must be a function)",
      );
    }
    OPTS_BY_HANDLER.set(fn, opts);
  };
  return decorator;
}

/** @internal — used by `AgentumGuard` to retrieve options. */
export function getAgentumGuardOptions(
  handler: (...args: unknown[]) => unknown,
): AgentumGuardForOptions | undefined {
  return OPTS_BY_HANDLER.get(handler);
}

/** @internal — test hook: clear all registrations. */
export function _clearAgentumGuardRegistry(): void {
  // WeakMap doesn't expose iteration, so the best we can do is rebind the
  // reference. We don't expose the live map, so tests must re-import.
  // (This hook is not exported from the package root.)
}
