import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'

const SYSTEM = `You are a DLP (Data Loss Prevention) product expert. When given a tool name, respond with ONLY a valid JSON object — no markdown, no prose, no code fences.

The JSON must match this exact shape:
{
  "isRealDlp": boolean,
  "confidence": "high" | "medium" | "low",
  "reason": "one sentence explanation",
  "toolData": {
    "label": "Official product name",
    "description": "2-3 sentence product description",
    "category": ["category1", "category2"],
    "website": "https://vendor.com/",
    "channelCoverage": {
      "email": "full" | "partial" | "addon" | "none",
      "web": "full" | "partial" | "addon" | "none",
      "saas-inline": "full" | "partial" | "addon" | "none",
      "saas-api": "full" | "partial" | "addon" | "none",
      "endpoint": "full" | "partial" | "addon" | "none",
      "genai": "full" | "partial" | "addon" | "none",
      "network": "full" | "partial" | "addon" | "none"
    },
    "modules": [
      { "id": "kebab-case-id", "label": "Module Name", "description": "One sentence." }
    ]
  }
}

Coverage levels: full = native full coverage, partial = limited or needs config, addon = separate paid add-on, none = not covered.
If isRealDlp is false, still fill label and description in toolData but set all channelCoverage to "none" and modules to [].
Be accurate based on your training knowledge. If unsure about a specific tool, set confidence to "low".`

export async function reviewDlpTool(
  toolName: string,
): Promise<{ result: unknown; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const response = await anthropic.messages.create(
      {
        model:      MODEL,
        max_tokens: 2048,
        system:     SYSTEM,
        messages:   [{ role: 'user', content: `Review this DLP tool: "${toolName}"` }],
      },
      { signal: controller.signal },
    )

    const raw = response.content[0].type === 'text' ? response.content[0].text.trim() : ''
    const json = raw.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/i, '')

    return {
      result:       JSON.parse(json),
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}
