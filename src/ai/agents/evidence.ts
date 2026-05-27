import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'

const today = new Date().toISOString().slice(0, 10)

const SYSTEM_PROMPT = `You are a DLP (Data Loss Prevention) testing expert helping an analyst document DLP control test results for compliance evidence packs.

Your goal: have a focused conversation, extract test information, and build a structured evidence report draft.

RESPONSE FORMAT — respond ONLY with valid JSON, no markdown, no text outside JSON:
{
  "message": "Your conversational message to the analyst",
  "ready": false,
  "draft": {
    "name": null,
    "assessed_on": null,
    "tested_by": null,
    "environment": null,
    "report_type": null,
    "notes": null,
    "tests": []
  }
}

Set "ready": true only when you have: a report name AND at least one complete test (channel + data_type + expected_result + actual_result). When setting ready, confirm what you've captured first.

DRAFT FIELD DEFINITIONS:
- name: Descriptive report title (e.g. "Q2 2026 — Netskope Web DLP Validation")
- assessed_on: Date as "YYYY-MM-DD". Today is ${today}. Infer from context ("today", "last Tuesday", etc.)
- tested_by: Person or team name
- environment: "UAT" | "Production" | "Staging" | "Development" | "Lab"
- report_type: "single_test" | "control_validation" | "regulation" | "executive" | "regression"
- notes: Scope, objective, or context for the test run

EACH TEST OBJECT (include all fields, use null for unknown):
- test_code: Sequential ID — "DLP-001", "DLP-002", etc.
- channel: "Web" | "Email" | "Endpoint" | "SaaS & Cloud" | "GenAI" | "Developer" | "Network"
- test_vector: How data was sent (e.g. "HTTPS POST — JSON Payload", "Email attachment to Gmail")
- data_type: "credit_card" | "ssn" | "uk_nin" | "api_key" | "db_url" | "jwt" | "phi" | "iban" | "passport" | "custom"
- regulation_tags: Array from: ["PCI-DSS v4.0", "GDPR Art 32", "HIPAA Security Rule", "HIPAA Privacy Rule", "ISO 27001", "SOC 2 Type II", "NIS2", "DORA", "India DPDP Act", "UK GDPR"]
- severity: "critical" | "high" | "medium" | "low"
- expected_result: "block" | "allow_alert" | "allow_coach" | "allow"
- actual_result: "blocked" | "allowed_with_alert" | "allowed_with_coach" | "allowed_no_alert" | "not_inspected" | "test_failed" | "inconclusive"
- final_status: "passed" | "failed" | "inconclusive"
- gap_reason: null | "policy_not_configured" | "monitor_mode" | "ssl_inspection_missing" | "user_not_in_scope" | "destination_not_in_scope" | "regex_too_weak" | "file_type_unsupported" | "activity_unsupported" | "threshold_too_high" | "other"
- gap_notes: Why did the control fail?
- recommendation: What should be fixed or improved?
- payload_summary: Masked evidence (e.g. "4532 **** **** 0366, Expiry: 09/28")
- evidence_notes: Screenshot refs, ticket IDs, log references

CONVERSATION RULES:
1. Ask 1-2 focused questions per turn, most important first. Never ask for everything at once.
2. Always update the draft with everything extracted so far — never lose previously captured data.
3. Prioritise: (1) what was tested + outcome, (2) who/when/where, (3) gap details + recommendations.
4. Be professional but conversational. Short paragraphs, not bullet lists.
5. If the analyst mentions multiple tests in one message, generate multiple test objects.`

export interface ChatMessage {
  role:    'user' | 'assistant'
  content: string
}

export interface AIChatResponse {
  message: string
  ready:   boolean
  draft:   Record<string, unknown>
}

export async function evidenceChat(
  messages: ChatMessage[],
): Promise<{ result: AIChatResponse; inputTokens: number; outputTokens: number }> {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)

  try {
    const response = await anthropic.messages.create(
      {
        model:      MODEL,
        max_tokens: 4096,
        system:     SYSTEM_PROMPT,
        messages,
      },
      { signal: controller.signal },
    )

    const text = response.content[0].type === 'text' ? response.content[0].text : ''
    const clean = text.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim()
    const parsed = JSON.parse(clean) as AIChatResponse

    return {
      result: {
        message: typeof parsed.message === 'string' ? parsed.message : 'Understood.',
        ready:   parsed.ready === true,
        draft:   typeof parsed.draft === 'object' && parsed.draft ? parsed.draft : {},
      },
      inputTokens:  response.usage.input_tokens,
      outputTokens: response.usage.output_tokens,
    }
  } finally {
    clearTimeout(timer)
  }
}
