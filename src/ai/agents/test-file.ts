import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'
import { parseAiJson } from '../../lib/parse-json'

const SYSTEM_PROMPT = `You are a DLP testing file generator. Create realistic test files containing clearly-marked synthetic sensitive data for DLP control validation.

RESPONSE FORMAT — respond ONLY with valid JSON, no markdown, no text outside the JSON object:
{
  "filename": "suggested_filename.ext",
  "fileType": "text",
  "mimeType": "text/plain",
  "description": "Brief description of what was generated",
  "content": "...file content..."
}

For any .xlsx or Excel request, use fileType "xlsx" and a JSON array string for content:
{
  "filename": "data.xlsx",
  "fileType": "xlsx",
  "mimeType": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "description": "...",
  "content": "[{\\"col1\\":\\"val1\\",\\"col2\\":\\"val2\\"}]"
}
The content must be a valid JSON array string of row objects with consistent column keys.

RULES:
1. Always mark content as SYNTHETIC DLP TEST DATA via a comment, header, or prefix — never omit this
2. Generate realistic-looking synthetic data: fake PEM base64, SSNs as XXX-XX-XXXX, credit card numbers starting 4111 1111 1111, AWS keys starting AKIA, etc.
3. Handle any format the user requests: .pem, .key, .env, .yaml, .yml, .json, .sql, .log, .csv, .conf, .toml, .ini, .xml, .txt, .gitconfig, .npmrc, Dockerfile, Kubernetes YAML, .md, .htpasswd, .p8, and any other text-based format
4. For binary formats (.db, .p12, .docx, .pdf): generate best-effort text representation and note in description that it is a text approximation
5. Never generate real working credentials, actual cryptographic keys, or executable malicious code
6. For data files (JSON, SQL, CSV, logs): include at least 10-20 realistic records with PII, financial data, or health data as appropriate
7. For credential and config files: produce a complete, realistic structure — proper PEM headers, real-looking key structure, full .env/YAML layout
8. Choose the right mimeType: text/plain for .pem/.key/.env/log files, application/json for .json, application/sql for .sql, text/csv for .csv, application/x-yaml for .yaml`

export interface GeneratedFileResult {
  filename:    string
  fileType:    'text' | 'xlsx'
  mimeType:    string
  description: string
  content:     string
}

export async function generateTestFile(
  prompt: string,
): Promise<{ result: GeneratedFileResult; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const response = await anthropic.messages.create(
      {
        model:      MODEL,
        max_tokens: 4096,
        system:     SYSTEM_PROMPT,
        messages:   [{ role: 'user', content: prompt }],
      },
      { signal: controller.signal },
    )

    const text = response.content[0].type === 'text' ? response.content[0].text : ''
    const parsed = parseAiJson<GeneratedFileResult>(text)

    return {
      result: parsed,
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}
