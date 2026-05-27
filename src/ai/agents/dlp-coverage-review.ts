import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'
import { parseAiJson } from '../../lib/parse-json'

export interface OrgDlpData {
  tools:           string[]
  modules:         Record<string, string[]>
  coverage_areas:  Record<string, string>
  policy_presence: string | null
  policy_mode:     string | null
  incident_review: string | null
  data_categories: unknown[]
  channelAnswers:  Record<string, Record<string, string>>
}

export interface CoverageGap {
  channel:     string
  severity:    'critical' | 'high' | 'medium' | 'low'
  description: string
}

export interface CoverageRecommendation {
  priority:    number
  title:       string
  description: string
}

export interface CoverageReviewResult {
  coverageScore:   number
  gaps:            CoverageGap[]
  recommendations: CoverageRecommendation[]
}

const SYSTEM_PROMPT = `You are a senior DLP architect reviewing an organisation's DLP coverage posture. Respond ONLY with valid JSON. No markdown, no prose, no code blocks.`

export async function reviewDlpCoverage(
  data: OrgDlpData,
): Promise<{ result: CoverageReviewResult; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const prompt = `You are a senior DLP architect reviewing an organisation's DLP coverage posture.

## Their DLP Tool Stack
Tools: ${JSON.stringify(data.tools)}
Modules per tool: ${JSON.stringify(data.modules)}
Coverage areas configured: ${JSON.stringify(data.coverage_areas)}

## Policy Maturity
Policy presence: ${data.policy_presence ?? 'unknown'}
Policy mode: ${data.policy_mode ?? 'unknown'}
Incident review: ${data.incident_review ?? 'unknown'}

## Priority Data Categories
${JSON.stringify(data.data_categories)}

## Channel Assessment Answers (per channel: question key → not_assessed | partial | covered)
${JSON.stringify(data.channelAnswers, null, 2)}

## DLP Channels to Assess
email, web, saas-inline, saas-api, endpoint, genai, network

Based on this data, identify:
1. Coverage gaps by DLP channel — channels with no tool coverage or primarily not_assessed answers
2. Mismatches between tool capability and actual assessment answers
3. Top 5 prioritised recommendations to improve DLP coverage

Respond ONLY with valid JSON in this exact shape:
{
  "coverageScore": <integer 0-100>,
  "gaps": [{ "channel": string, "severity": "critical"|"high"|"medium"|"low", "description": string }],
  "recommendations": [{ "priority": <1-5>, "title": string, "description": string }]
}`

    const response = await anthropic.messages.create(
      {
        model:      MODEL,
        max_tokens: 4096,
        system:     SYSTEM_PROMPT,
        messages:   [{ role: 'user', content: prompt }],
      },
      { signal: controller.signal },
    )

    const raw    = response.content[0].type === 'text' ? response.content[0].text : ''
    const parsed = parseAiJson<CoverageReviewResult>(raw)

    return {
      result: {
        coverageScore:   typeof parsed.coverageScore === 'number' ? parsed.coverageScore : 0,
        gaps:            Array.isArray(parsed.gaps)            ? parsed.gaps            : [],
        recommendations: Array.isArray(parsed.recommendations) ? parsed.recommendations : [],
      },
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}
