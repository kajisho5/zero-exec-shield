// A minimal JSON Schema validator that interprets only the keywords used in schemas/findings.schema.json (test-only).
// Supports: $ref (#/$defs/...), type, const, enum, pattern, minimum, required, properties, additionalProperties:false, items, uniqueItems, if/then/else, not
import { readFileSync } from 'node:fs';

type S = Record<string, unknown>;
export const FINDINGS_SCHEMA = JSON.parse(readFileSync(new URL('../../../schemas/findings.schema.json', import.meta.url), 'utf8')) as S;

const typeOf = (v: unknown) => (v === null ? 'null' : Array.isArray(v) ? 'array' : Number.isInteger(v) ? 'integer' : typeof v);

/** List of JSON-Pointer-like locations and reasons of violations (empty if valid). */
export function validate(v: unknown, schema: S = FINDINGS_SCHEMA, root: S = FINDINGS_SCHEMA, at = ''): string[] {
  const errs: string[] = [];
  const known = new Set(['$schema', '$id', 'title', 'description', '$defs', '$ref', 'type', 'const', 'enum', 'pattern', 'required', 'properties', 'additionalProperties', 'items', 'uniqueItems', 'if', 'then', 'else', 'not', 'minimum']);
  for (const k of Object.keys(schema)) if (!known.has(k)) throw new Error(`unsupported keyword ${k} at ${at}`);
  if (typeof schema['$ref'] === 'string') {
    const target = (schema['$ref'] as string).replace(/^#\//, '').split('/').reduce<unknown>((o, k) => (o as S)[k], root) as S;
    errs.push(...validate(v, target, root, at));
  }
  if (schema['type'] !== undefined) {
    const types = Array.isArray(schema['type']) ? schema['type'] as string[] : [schema['type'] as string];
    const t = typeOf(v);
    if (!types.some((x) => x === t || (x === 'number' && t === 'integer'))) return [...errs, `${at}: type ${t} not in ${types.join('|')}`];
  }
  if ('const' in schema && JSON.stringify(v) !== JSON.stringify(schema['const'])) errs.push(`${at}: const`);
  if (Array.isArray(schema['enum']) && !(schema['enum'] as unknown[]).some((e) => JSON.stringify(e) === JSON.stringify(v))) errs.push(`${at}: enum ${JSON.stringify(v)}`);
  if (typeof schema['minimum'] === 'number' && typeof v === 'number' && v < (schema['minimum'] as number)) errs.push(`${at}: minimum ${schema['minimum']}`);
  if (typeof schema['pattern'] === 'string' && typeof v === 'string' && !new RegExp(schema['pattern'] as string, 'u').test(v)) errs.push(`${at}: pattern ${schema['pattern']} ${JSON.stringify(v)}`);
  if (v && typeof v === 'object' && !Array.isArray(v)) {
    const o = v as S;
    for (const r of (schema['required'] as string[] | undefined) ?? []) if (!(r in o)) errs.push(`${at}: required ${r}`);
    const props = (schema['properties'] as Record<string, S> | undefined) ?? {};
    for (const [k, x] of Object.entries(o)) {
      if (props[k]) errs.push(...validate(x, props[k], root, `${at}/${k}`));
      else if (schema['additionalProperties'] === false) errs.push(`${at}: additional property ${k}`);
    }
  }
  if (Array.isArray(v)) {
    if (schema['items']) v.forEach((x, i) => errs.push(...validate(x, schema['items'] as S, root, `${at}/${i}`)));
    if (schema['uniqueItems'] && new Set(v.map((x) => JSON.stringify(x))).size !== v.length) errs.push(`${at}: uniqueItems`);
  }
  if (schema['if']) {
    const ok = validate(v, schema['if'] as S, root, at).length === 0;
    const branch = ok ? schema['then'] : schema['else'];
    if (branch) errs.push(...validate(v, branch as S, root, at));
  }
  if (schema['not'] && validate(v, schema['not'] as S, root, at).length === 0) errs.push(`${at}: not`);
  return errs;
}
