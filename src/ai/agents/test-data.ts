import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'
import { parseAiJson } from '../../lib/parse-json'

const SYSTEM_PROMPT = `You are a DLP test data generator. Produce realistic but entirely synthetic (fake) data for testing Data Loss Prevention policies. Respond ONLY with raw JSON — no markdown, no prose, no code blocks.

Required JSON structure:
{
  "columns": ["col_name", ...],
  "records": [{"col_name": "value", ...}, ...],
  "description": "One-line summary of what was generated"
}

Rules:
- CRITICAL: Generate ONLY the exact columns the user asks for. If the user asks for "credit card, cvv, expiry" generate exactly those 3 columns — do NOT add name, email, address, record_id, or any other column unless explicitly requested. Strict column matching.
- All data is synthetic — no real people, no real account numbers, no real credentials
- Vary values across every record — no two rows should be identical
- Column names: snake_case, no spaces
- Dates: MM/DD/YYYY format
- US SSN: ###-##-#### format (e.g. 523-45-6789)
- Phone (US): (###) ###-#### format
- Credit cards: generate a realistic mix of card types and numbers — Visa (16 digits, starts with 4), Mastercard (16 digits, starts with 51-55), Amex (15 digits, starts with 34 or 37), Discover (16 digits, starts with 6011) — vary card types across records
- API keys / secrets: always prefix with SYNTHETIC_ (e.g. sk_test_SYNTHETIC_KEY_001)
- AWS access keys: start with AKIAIOSFODNN followed by synthetic chars
- Passwords: obviously fake patterns like P@ssw0rd_TEST_001
- JWTs: eyJhbGciOiJIUzI1NiJ9.SYNTHETIC_PAYLOAD_N.SYNTHETIC_SIG
- Database URLs: use db.example.com with synthetic credentials
- Focus on DLP-relevant data types: PII, credentials, financial data, healthcare, identity documents
- Generate exactly the requested number of records`

export interface GeneratedData {
  columns:     string[]
  records:     Record<string, string>[]
  description: string
}

export async function generateTestData(
  prompt: string,
  rowCount: number,
): Promise<{ result: GeneratedData; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const response = await anthropic.messages.create(
      {
        model:      MODEL,
        max_tokens: 8192,
        system:     SYSTEM_PROMPT,
        messages:   [{
          role:    'user',
          content: `Generate DLP test data for: ${prompt}\n\nGenerate exactly ${rowCount} records.`,
        }],
      },
      { signal: controller.signal },
    )

    if (response.stop_reason === 'max_tokens') {
      throw new Error('Response was too long — try fewer rows or a simpler description')
    }

    const text = response.content[0].type === 'text' ? response.content[0].text : ''
    const parsed = parseAiJson<GeneratedData>(text)

    return {
      result: {
        columns:     parsed.columns as string[],
        records:     (parsed.records as unknown[]).filter(
          (r): r is Record<string, string> => typeof r === 'object' && r !== null,
        ),
        description: parsed.description,
      },
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}
