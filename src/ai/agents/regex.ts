import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'

const SYSTEM_PROMPT = `You are a DLP (Data Loss Prevention) regex expert.
When given a description of what to match, respond ONLY with a valid JSON object.
No markdown, no prose, no code blocks — raw JSON only.

The JSON must have exactly this structure:
{
  "title": "<short pattern name, 2-5 words, suitable as a library entry title>",
  "pattern": "<regex pattern string, no delimiters, no flags>",
  "flags": "<string containing only g, i, m characters — always include g>",
  "explanation": "<plain English explanation of how the pattern works, with each major component on its own line separated by \\n>",
  "testExamples": ["<string that WILL match>", ...],
  "nonMatchExamples": ["<string that will NOT match>", ...],
  "confidence": {
    "matchAccuracy": "good|fair|poor",
    "falsePositiveRisk": "low|medium|high",
    "anchoring": "strong|weak",
    "contextRequired": true|false,
    "dlpSeverity": "critical|high|medium|low",
    "recommendation": "<one sentence: how to deploy this pattern in a DLP tool>"
  }
}

DLP TOOL COMPATIBILITY — mandatory, non-negotiable:
- Use ONLY: character classes [0-9] [A-Za-z] [A-Z0-9], shorthand \\d \\w \\s and their negations, word boundaries \\b, simple quantifiers {n} {n,m} ? + *, non-capturing groups (?:...), capturing groups ()
- NEVER use lookaheads: (?=...) or (?!...)
- NEVER use lookbehinds: (?<=...) or (?<!...)
- NEVER use backreferences: \\1 or named groups (?<name>...) or (?P<name>...)
- NEVER use atomic groups (?>...) or possessive quantifiers *+ ++ ?+
- NEVER use conditional patterns (?(condition)...)
- If precision requires excluding edge cases, accept those edge cases and note them in the explanation rather than using lookaheads
- Patterns must work in Netskope, Symantec DLP, Microsoft Purview, and standard regex engines

General rules:
- flags must only contain g, i, m — always include g
- Prefer \\b word boundaries for anchoring — avoids partial matches
- Avoid catastrophic backtracking — no nested quantifiers on overlapping character classes
- testExamples: 3-5 realistic strings that match the pattern
- nonMatchExamples: 2-3 strings that should NOT match, to verify precision
- Focus on DLP use cases: PII, credentials, financial data, identity documents`

export interface AiRegexResult {
  title:            string
  pattern:          string
  flags:            string
  explanation:      string
  testExamples:     string[]
  nonMatchExamples: string[]
  confidence: {
    matchAccuracy:     'good' | 'fair' | 'poor'
    falsePositiveRisk: 'low' | 'medium' | 'high'
    anchoring:         'strong' | 'weak'
    contextRequired:   boolean
    dlpSeverity:       'critical' | 'high' | 'medium' | 'low'
    recommendation:    string
  }
}

export async function generateRegex(prompt: string): Promise<{ result: AiRegexResult; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const response = await anthropic.messages.create(
      {
        model:      MODEL,
        max_tokens: 2048,
        system:     SYSTEM_PROMPT,
        messages:   [{ role: 'user', content: `Generate a DLP regex pattern for: ${prompt}` }],
      },
      { signal: controller.signal },
    )

    const text = response.content[0].type === 'text' ? response.content[0].text : ''
    const clean = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim()
    const parsed = JSON.parse(clean) as AiRegexResult

    const title = typeof parsed.title === 'string' && parsed.title.trim()
      ? parsed.title.trim()
      : prompt.slice(0, 40)

    return {
      result: { ...parsed, title },
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}
