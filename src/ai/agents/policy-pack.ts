import { z } from 'zod'
import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'
import { parseAiJson } from '../../lib/parse-json'

export interface PolicyPackInput {
  orgProfile: {
    industry:        string | null
    regions:         string[]
    tools:           string[]
    data_categories: string[]
    top_priorities:  string[]
    policy_presence: string | null
    policy_mode:     string | null
  }
  coverageScore:  number
  coverageGaps:   Array<{ channel: string; severity: string; description: string }>
  appCounts: {
    enterprise_approved:      number
    approved_with_conditions: number
    restricted:               number
    prohibited:               number
  }
  existingPolicyFamilies: string[]
}

const VALID_ACTIONS = ['allow', 'monitor', 'alert', 'coach', 'coach-ack', 'coach-just', 'block'] as const
const VALID_LABELS  = ['public', 'internal', 'confidential', 'highly-confidential', 'secret', 'all'] as const

const PolicyPackRecommendationSchema = z.object({
  name:                      z.string().min(1),
  description:               z.string().min(1),
  policy_type:               z.enum(['usage', 'data-handling', 'approved-use', 'prohibited']),
  policy_family:             z.string().min(1),
  data_classification_label: z.enum(VALID_LABELS),
  primary_action:            z.enum(VALID_ACTIONS),
  scope_all_apps:            z.boolean(),
  priority:                  z.number().int().min(1).max(20),
  rationale:                 z.string().min(1),
})

export const PolicyPackResultSchema = z.object({
  policies: z.array(PolicyPackRecommendationSchema).min(1).max(10),
  summary:  z.string().min(1),
})

export type PolicyPackResult         = z.infer<typeof PolicyPackResultSchema>
export type PolicyPackRecommendation = z.infer<typeof PolicyPackRecommendationSchema>

const SYSTEM_PROMPT = `You are a senior DLP architect generating targeted DLP policy recommendations. Respond ONLY with valid JSON. No markdown, no prose, no code blocks.`

export async function generatePolicyPack(
  input: PolicyPackInput,
): Promise<{ result: PolicyPackResult; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const criticalGaps = input.coverageGaps.filter(g => g.severity === 'critical' || g.severity === 'high')
    const allGaps      = input.coverageGaps

    const prompt = `You are a senior DLP architect generating targeted GenAI DLP policy recommendations for an organisation.

## Organisation Profile
Industry: ${input.orgProfile.industry ?? 'unknown'}
Regions: ${JSON.stringify(input.orgProfile.regions)}
DLP Tools: ${JSON.stringify(input.orgProfile.tools)}
Priority Data Categories: ${JSON.stringify(input.orgProfile.data_categories)}
Top Priorities: ${JSON.stringify(input.orgProfile.top_priorities)}
Policy Maturity: presence=${input.orgProfile.policy_presence ?? 'unknown'}, mode=${input.orgProfile.policy_mode ?? 'unknown'}

## Current DLP Coverage
Coverage Score: ${input.coverageScore}/100
Critical/High Gaps: ${JSON.stringify(criticalGaps)}
All Gaps: ${JSON.stringify(allGaps)}

## GenAI App Landscape
Enterprise Approved Apps: ${input.appCounts.enterprise_approved}
Approved with Conditions: ${input.appCounts.approved_with_conditions}
Restricted Apps: ${input.appCounts.restricted}
Prohibited Apps: ${input.appCounts.prohibited}

## Existing Policy Families (do NOT duplicate these)
${JSON.stringify(input.existingPolicyFamilies)}

## Task
Generate 3–7 targeted GenAI DLP policy recommendations that:
1. Directly address the highest-severity coverage gaps above
2. Account for the organisation's industry and region (GDPR for European regions, HIPAA for healthcare industry)
3. Reflect the priority data categories and top priorities
4. Do NOT duplicate any existing policy family listed above
5. Are ordered by urgency (priority 1 = most urgent)

Policy type rules (MUST follow):
- "prohibited" policies MUST use primary_action "block"
- "approved-use" policies MUST use primary_action "allow"
- "data-handling" policies typically use "monitor", "alert", "coach", "coach-ack", "coach-just", or "block"
- "usage" policies typically use "monitor", "alert", "coach", or "allow"

Valid primary_action values: ${VALID_ACTIONS.join(' | ')}
Valid data_classification_label values: ${VALID_LABELS.join(' | ')}

Respond ONLY with valid JSON in this exact shape:
{
  "policies": [
    {
      "name": string,
      "description": string,
      "policy_type": "usage"|"data-handling"|"approved-use"|"prohibited",
      "policy_family": string,
      "data_classification_label": "public"|"internal"|"confidential"|"highly-confidential"|"secret"|"all",
      "primary_action": "allow"|"monitor"|"alert"|"coach"|"coach-ack"|"coach-just"|"block",
      "scope_all_apps": boolean,
      "priority": <integer 1-20>,
      "rationale": string
    }
  ],
  "summary": string
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
    const parsed = parseAiJson<unknown>(raw)
    const result = PolicyPackResultSchema.parse(parsed)

    return {
      result,
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}
