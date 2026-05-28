import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'
import { parseAiJson } from '../../lib/parse-json'

const SYSTEM_PROMPT = `You are a DLP security researcher. You evaluate GenAI applications from the personal/consumer tier perspective — the free or standard plan that employees actually use without IT provisioning.
Respond ONLY with valid JSON. No markdown, no prose, no code blocks.

Field values MUST be one of exactly:
- AppFields: "yes" | "no" | "partial" | "enterprise-only" | "tier-dependent" | "configurable" | "no-published" | "na"
- DLPActivities: "enforcement" | "monitoring" | "partial" | "no-published" | "not-supported"
- BreachInfo positive fields: same as AppFields
- BreachInfo negative fields (recent_breach, older_breach): "yes" = bad, "no" = good

Definitions:
- yes: fully available/implemented on personal/free tier
- no: not available/implemented
- partial: partly available but incomplete
- enterprise-only: feature exists but requires enterprise tier (NOT available to personal users)
- tier-dependent: depends on which personal subscription tier (free vs pro)
- configurable: user can configure it on personal tier
- no-published: information not publicly available
- na: not applicable for this app type
- enforcement: DLP can block/enforce on this activity
- monitoring: DLP can observe but not enforce
- not-supported: DLP cannot intercept this activity at all

Use "no-published" when you cannot verify a claim. Do not guess.`

export async function researchApp(app: {
  app_id:   string
  app_name: string
  vendor:   string
  domain:   string
  app_type: string
}): Promise<{ result: unknown; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const prompt = `Research this GenAI application from the personal/consumer tier perspective (free or standard plan — what employees actually use).

App: ${app.app_name}
Vendor: ${app.vendor}
Domain: ${app.domain}
Type: ${app.app_type}

Return a JSON object with exactly this structure:
{
  "fields": {
    "dpa_available": "...", "customer_owns_data": "...", "trains_on_customer_data": "...",
    "opt_out_of_training": "...", "data_retention": "...", "data_deletion": "...",
    "data_residency": "...", "subprocessor_list": "...", "pii_sharing_third_parties": "...",
    "data_sharing_genai_vendor": "...", "soc2": "...", "iso27001": "...", "iso27018": "...",
    "fedramp": "...", "pci_dss": "...", "hipaa_baa": "...", "encryption_at_rest": "...",
    "encryption_in_transit": "...", "tenant_segregation": "...", "model_provider_clear": "...",
    "prompt_retention_controls": "...", "connectors_agents_risk": "..."
  },
  "dlp": {
    "post_prompt": "...", "upload": "...", "login_instance": "...", "edit": "...",
    "response": "...", "download": "...", "attach": "..."
  },
  "breach_info": {
    "recent_breach": "...", "older_breach": "...", "breach_disclosed": "...",
    "source_disclosure": "...", "breach_remediated": "...",
    "breach_name": null, "breach_date": null, "breach_description": null
  },
  "notes": "Brief factual summary of key security characteristics and notable risks for personal-tier users."
}`

    const response = await anthropic.messages.create(
      { model: MODEL, max_tokens: 4096, system: SYSTEM_PROMPT, messages: [{ role: 'user', content: prompt }] },
      { signal: controller.signal },
    )

    const raw = response.content[0].type === 'text' ? response.content[0].text : ''
    return {
      result: parseAiJson(raw),
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}

export async function identifyApp(
  searchTerm: string,
): Promise<{ result: unknown; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const prompt = `A user searched for a GenAI application: "${searchTerm}"

Identify this specific application. Return a JSON object:
{
  "app_id": "lowercase-hyphenated-id e.g. chatgpt or github-copilot",
  "app_name": "Official display name",
  "vendor": "Company/vendor name",
  "domain": "Primary domain e.g. chat.openai.com",
  "app_type": "One of: AI Assistant | Code Assistant | Image Generator | AI Writing | AI Search | AI Analytics | AI Communication | AI Productivity",
  "logo_letter": "Single uppercase letter for the logo",
  "logo_bg": "Hex color matching the brand e.g. #10a37f",
  "description": "2-3 sentence factual description of what the app does and its primary use cases in an enterprise context. Focus on what data employees share with it.",
  "headquarters": "City, Country (e.g. San Francisco, USA) or null if unknown",
  "founded_year": 2022,
  "employee_count": "e.g. 1-50 | 51-200 | 201-500 | 501-2000 | 2001-10000 | 10000+ or null",
  "primary_use_cases": ["array", "of", "3-5", "short", "use", "case", "strings"]
}

If this is not a real, identifiable GenAI application, return the JSON value null.`

    const response = await anthropic.messages.create(
      { model: MODEL, max_tokens: 512, system: SYSTEM_PROMPT, messages: [{ role: 'user', content: prompt }] },
      { signal: controller.signal },
    )

    const raw = response.content[0].type === 'text' ? response.content[0].text : 'null'
    return {
      result: parseAiJson(raw, 'null'),
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}

export async function discoverNewApps(
  existingAppIds: string[],
): Promise<{ result: unknown[]; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const prompt = `You are a GenAI market researcher tracking enterprise-relevant AI applications.

Existing apps already in the catalog (do NOT suggest these):
${existingAppIds.join(', ')}

Identify up to 5 significant GenAI applications that enterprises are actively using or evaluating for work, that are NOT in the catalog above. Focus on productivity, coding, content, or data AI tools used by knowledge workers.

Return a JSON array (may be empty if nothing significant to add):
[
  {
    "app_id": "lowercase-hyphenated-id",
    "app_name": "Display Name",
    "vendor": "Company Name",
    "domain": "app.example.com",
    "app_type": "one of: AI Assistant | Code Assistant | Image Generator | AI Writing | AI Search | AI Analytics | AI Communication | AI Productivity",
    "logo_letter": "Single uppercase letter",
    "logo_bg": "A hex color code like #1a1a2e that suits the brand",
    "description": "2-3 sentence factual description of what the app does in an enterprise context.",
    "headquarters": "City, Country or null",
    "founded_year": null,
    "employee_count": null,
    "primary_use_cases": ["use case 1", "use case 2"]
  }
]

Only include apps with significant enterprise adoption or strong growth trajectory. Return JSON only.`

    const response = await anthropic.messages.create(
      { model: MODEL, max_tokens: 1024, system: SYSTEM_PROMPT, messages: [{ role: 'user', content: prompt }] },
      { signal: controller.signal },
    )

    const raw = response.content[0].type === 'text' ? response.content[0].text : '[]'
    return {
      result: parseAiJson<unknown[]>(raw, '[]'),
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}
