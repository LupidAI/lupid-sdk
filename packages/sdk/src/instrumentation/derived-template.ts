/**
 * TypeScript evaluator for the derived-template DSL.
 *
 * Grammar (parity target with the Rust parser at
 * `crates/agentum-identity-schema/src/derive.rs`):
 *
 *   template := (LITERAL | INTERP)*
 *   INTERP   := "${" ident pipeline? "}"
 *   pipeline := ("|" op arg)+
 *   op       := "regex_extract" | "lowercase" | "uppercase" | "default"
 *   arg      := '"' (escape | any-non-quote)* '"'
 *   escape   := "\\" ("\\" | '"')
 *
 *   - `lowercase` / `uppercase` accept no argument; everything else takes a
 *     required double-quoted literal argument.
 *   - Pipe operators evaluate left-to-right; `null` propagates through every
 *     operator EXCEPT `default "X"`, which substitutes the literal.
 *   - The final returned value is `null` iff the interpolation result was
 *     `null` AND the template contains no surrounding literal text. Templates
 *     with mixed literal + interpolation always return a string (with the
 *     null interpolation rendered as the empty string).
 *
 * The Rust evaluator (`DerivedTemplate::evaluate()`) is not yet implemented,
 * so cross-language parity fixtures are pending. This file is unit-tested
 * against its own grammar in
 * `tests/instrumentation/derived-template.test.ts`.
 */

type Op =
  | { kind: "regex_extract"; pattern: string }
  | { kind: "lowercase" }
  | { kind: "uppercase" }
  | { kind: "default"; literal: string };

type Segment =
  | { kind: "literal"; text: string }
  | { kind: "interp"; name: string; ops: Op[] };

class TemplateParseError extends Error {
  constructor(message: string) {
    super(`derived-template: ${message}`);
    this.name = "TemplateParseError";
  }
}

function tokenize(tmpl: string): Segment[] {
  const segments: Segment[] = [];
  let i = 0;
  let literal = "";
  while (i < tmpl.length) {
    if (tmpl[i] === "$" && tmpl[i + 1] === "{") {
      if (literal.length > 0) {
        segments.push({ kind: "literal", text: literal });
        literal = "";
      }
      // Find matching `}` — interpolations may not nest, so a plain scan is
      // sufficient. Quoted strings can contain `}`, so respect quote state.
      let j = i + 2;
      let inQuote = false;
      let escaped = false;
      while (j < tmpl.length) {
        const ch = tmpl[j];
        if (escaped) {
          escaped = false;
        } else if (ch === "\\" && inQuote) {
          escaped = true;
        } else if (ch === '"') {
          inQuote = !inQuote;
        } else if (ch === "}" && !inQuote) {
          break;
        }
        j += 1;
      }
      if (j >= tmpl.length) {
        throw new TemplateParseError(`unterminated interpolation in ${JSON.stringify(tmpl)}`);
      }
      const inner = tmpl.slice(i + 2, j);
      segments.push(parseInterpolation(inner));
      i = j + 1;
    } else {
      literal += tmpl[i];
      i += 1;
    }
  }
  if (literal.length > 0) {
    segments.push({ kind: "literal", text: literal });
  }
  return segments;
}

function parseInterpolation(inner: string): Segment {
  // Split on `|` while respecting quoted strings (with `\\` and `\"` escapes).
  const parts: string[] = [];
  let buf = "";
  let inQuote = false;
  let escaped = false;
  for (let i = 0; i < inner.length; i += 1) {
    const ch = inner[i] as string;
    if (escaped) {
      buf += ch;
      escaped = false;
      continue;
    }
    if (inQuote) {
      if (ch === "\\") {
        // Preserve the escape sequence so the arg parser sees `\"` / `\\`.
        buf += ch;
        escaped = true;
        continue;
      }
      buf += ch;
      if (ch === '"') inQuote = false;
      continue;
    }
    if (ch === '"') {
      inQuote = true;
      buf += ch;
      continue;
    }
    if (ch === "|") {
      parts.push(buf);
      buf = "";
      continue;
    }
    buf += ch;
  }
  parts.push(buf);

  const first = (parts[0] ?? "").trim();
  if (first.length === 0) {
    throw new TemplateParseError("empty dimension name in interpolation");
  }
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(first)) {
    throw new TemplateParseError(`invalid dimension name '${first}'`);
  }
  const ops: Op[] = [];
  for (let k = 1; k < parts.length; k += 1) {
    ops.push(parseOp((parts[k] ?? "").trim()));
  }
  return { kind: "interp", name: first, ops };
}

function parseOp(spec: string): Op {
  if (spec.length === 0) {
    throw new TemplateParseError("empty pipe operator");
  }
  // Identifier head then optional whitespace then optional quoted arg.
  const nameMatch = /^([A-Za-z_][A-Za-z0-9_]*)\s*(.*)$/s.exec(spec);
  if (!nameMatch) {
    throw new TemplateParseError(`unparseable pipe operator '${spec}'`);
  }
  const name = nameMatch[1] as string;
  const rest = (nameMatch[2] ?? "").trim();

  switch (name) {
    case "lowercase":
    case "uppercase": {
      if (rest.length > 0) {
        throw new TemplateParseError(`'${name}' takes no argument; got '${rest}'`);
      }
      return { kind: name };
    }
    case "regex_extract":
    case "default": {
      if (rest.length === 0) {
        throw new TemplateParseError(`'${name}' requires a quoted argument`);
      }
      const arg = parseQuotedArg(rest);
      return name === "regex_extract"
        ? { kind: "regex_extract", pattern: arg }
        : { kind: "default", literal: arg };
    }
    default:
      throw new TemplateParseError(`unknown pipe operator '${name}'`);
  }
}

function parseQuotedArg(src: string): string {
  if (src[0] !== '"') {
    throw new TemplateParseError(`expected '\"' at start of arg; got '${src}'`);
  }
  let out = "";
  let i = 1;
  let closed = false;
  while (i < src.length) {
    const ch = src[i] as string;
    if (ch === "\\") {
      const next = src[i + 1];
      if (next === "\\" || next === '"') {
        out += next;
        i += 2;
        continue;
      }
      throw new TemplateParseError(`invalid escape '\\${next ?? ""}'`);
    }
    if (ch === '"') {
      closed = true;
      i += 1;
      break;
    }
    out += ch;
    i += 1;
  }
  if (!closed) {
    throw new TemplateParseError(`unterminated quoted arg in '${src}'`);
  }
  // Reject trailing junk after the close-quote.
  if (i < src.length && src.slice(i).trim().length > 0) {
    throw new TemplateParseError(`trailing characters after quoted arg: '${src.slice(i)}'`);
  }
  return out;
}

function applyOp(op: Op, value: string | null): string | null {
  if (op.kind === "default") {
    return value ?? op.literal;
  }
  if (value === null) return null;
  switch (op.kind) {
    case "lowercase":
      return value.toLowerCase();
    case "uppercase":
      return value.toUpperCase();
    case "regex_extract": {
      let re: RegExp;
      try {
        re = new RegExp(op.pattern);
      } catch (err) {
        throw new TemplateParseError(
          `invalid regex '${op.pattern}': ${(err as Error).message}`,
        );
      }
      const match = re.exec(value);
      if (!match) return null;
      // First capture group if present, otherwise the full match.
      return match[1] ?? match[0] ?? null;
    }
    default: {
      const _exhaustive: never = op;
      void _exhaustive;
      return null;
    }
  }
}

/**
 * Evaluate a derived-template string against the dimensions already resolved
 * in this pass (`resolved`). Earlier-resolved dimensions may be referenced;
 * referencing a dimension not yet in `resolved` yields `null` (which then
 * propagates through any non-`default` pipe op).
 */
export function evaluateTemplate(
  tmpl: string,
  resolved: Record<string, string | null>,
): string | null {
  const segments = tokenize(tmpl);
  if (segments.length === 0) return "";

  // Special-case the lone-interpolation template: a template that is exactly
  // one `${...}` segment with no surrounding literal returns `null` when its
  // pipeline result is `null`. Mixed templates render `null` as the empty
  // string so the literal prefix/suffix still appears.
  if (segments.length === 1) {
    const only = segments[0] as Segment;
    if (only.kind === "interp") {
      let value: string | null = resolved[only.name] ?? null;
      for (const op of only.ops) {
        value = applyOp(op, value);
      }
      return value;
    }
    return only.text;
  }

  let out = "";
  for (const seg of segments) {
    if (seg.kind === "literal") {
      out += seg.text;
      continue;
    }
    let value: string | null = resolved[seg.name] ?? null;
    for (const op of seg.ops) {
      value = applyOp(op, value);
    }
    out += value ?? "";
  }
  return out;
}

export { TemplateParseError };
