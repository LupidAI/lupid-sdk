/**
 * H4 unit tests for `makeBlockNoticeText` — the helper that builds the
 * human-readable deny notice spliced into LLM responses on a policy
 * deny. The format MUST remain backward-compatible (consumers grep for
 * the leading `[!] Agentum blocked` line), with the new metadata
 * appended only when the caller supplies a deny code or rule id.
 */

import { makeBlockNoticeText } from "../src/instrumentation/_parsers";

describe("makeBlockNoticeText", () => {
  test("legacy 3-arg call returns the unchanged format", () => {
    const text = makeBlockNoticeText("send_email", `{"to":"a@b.c"}`, "no smtp");
    // Existing assertions across the codebase grep these substrings; they
    // must remain stable.
    expect(text).toMatch(/^\[!\] Agentum blocked send_email — no smtp/);
    expect(text).toContain(`Arguments: {"to":"a@b.c"}`);
    // No trailing metadata line when meta is omitted.
    expect(text).not.toMatch(/^\[code=/m);
    expect(text).not.toMatch(/^\[rule=/m);
  });

  test("with denyCode only, appends [code=...] trailer", () => {
    const text = makeBlockNoticeText("rm_rf", "{}", "destructive", {
      denyCode: "deny_cedar_policy",
    });
    expect(text).toContain("[!] Agentum blocked rm_rf — destructive");
    expect(text).toMatch(/\[code=deny_cedar_policy\]$/);
    expect(text).not.toMatch(/rule=/);
  });

  test("with ruleId only, appends [rule=...] trailer", () => {
    const text = makeBlockNoticeText("rm_rf", "{}", "destructive", {
      ruleId: "policy42",
    });
    expect(text).toMatch(/\[rule=policy42\]$/);
    expect(text).not.toMatch(/code=/);
  });

  test("with both denyCode and ruleId, joins on comma", () => {
    const text = makeBlockNoticeText("send_email", "{}", "no smtp", {
      denyCode: "deny_cedar_policy",
      ruleId: "forbid_send_email",
    });
    expect(text).toMatch(/\[code=deny_cedar_policy, rule=forbid_send_email\]$/);
  });

  test("undefined fields in meta do not appear in trailer", () => {
    const text = makeBlockNoticeText("rm_rf", "{}", "destructive", {
      denyCode: "deny_cedar_policy",
      ruleId: undefined,
    });
    expect(text).toMatch(/\[code=deny_cedar_policy\]$/);
    expect(text).not.toContain("rule=undefined");
  });

  test("falls back to a generic reason when none provided", () => {
    const text = makeBlockNoticeText("x", "{}", undefined);
    expect(text).toMatch(/policy rule matched/);
  });
});
