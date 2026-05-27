import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'
import { parseAiJson } from '../../lib/parse-json'

const SYSTEM_PROMPT = `You are a DLP data classification expert. Given an organisation's classification labels and a list of data types, suggest the most appropriate classification label for each data type. Respond ONLY with a valid JSON array. No markdown, no explanation outside the JSON.`

export interface DataTypeInput {
  id:       string
  name:     string
  examples?: string[]
  notes?:   string
}

export interface LabelInput {
  id:          string
  name:        string
  description?: string
  priority:    number
}

export interface ClassificationSuggestion {
  data_type_id: string
  label_name:   string
  confidence:   number
  reasoning:    string
}

export async function suggestClassifications(
  dataTypes: DataTypeInput[],
  labels:    LabelInput[],
): Promise<{ result: ClassificationSuggestion[]; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const userPrompt = `Classification labels (priority 1 = highest risk):
${labels.map(l => `${l.priority}. "${l.name}": ${l.description ?? ''}`).join('\n')}

Data types to classify:
${dataTypes.map(d => `- id: "${d.id}", name: "${d.name}", examples: [${(d.examples ?? []).slice(0, 3).join(', ')}]${d.notes ? `, notes: "${d.notes}"` : ''}`).join('\n')}

Return JSON array:
[{ "data_type_id": "uuid", "label_name": "exact label name from list above", "confidence": 0.0-1.0, "reasoning": "one sentence" }]`

    const response = await anthropic.messages.create(
      {
        model:      MODEL,
        max_tokens: 4096,
        system:     SYSTEM_PROMPT,
        messages:   [{ role: 'user', content: userPrompt }],
      },
      { signal: controller.signal },
    )

    const raw    = response.content[0].type === 'text' ? response.content[0].text : '[]'
    const parsed = parseAiJson<ClassificationSuggestion[]>(raw, '[]')

    return {
      result:       parsed,
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}
