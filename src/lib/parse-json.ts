/**
 * Strips markdown code fences that AI models sometimes wrap around JSON responses,
 * then parses the result. Pass a fallback string (e.g. '{}' or '[]') for responses
 * that should default to an empty value rather than throw on empty input.
 */
export function parseAiJson<T>(raw: string, fallback = ''): T {
  const clean = raw
    .replace(/^```(?:\w+)?\s*/m, '')
    .replace(/\s*```\s*$/m, '')
    .trim()
  return JSON.parse(clean || fallback) as T
}
