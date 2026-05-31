import { Router } from 'express'
import { z } from 'zod'
import { anthropic, MODEL } from '../../lib/anthropic'
import { logAiRun } from '../../lib/ai-log'
import { config } from '../../config'

const router = Router()

const ALLOWED_TOKENS = new Set([
  '{{APP}}', '{{USER}}', '{{POLICY_NAME}}', '{{ACTIVITY}}', '{{HOST}}', '{{URL}}',
  '{{CATEGORY}}', '{{FILENAME}}', '{{LABEL}}', '{{DATA_TYPE}}', '{{DETECTION_SOURCE}}',
  '{{DATE_TIME}}', '{{BUSINESS_JUSTIFICATION}}', '{{SUPPORT_CONTACT}}', '{{EXCEPTION_URL}}',
])

const SYSTEM_PROMPT = `You are an enterprise GenAI DLP coaching message assistant.

Your job is to draft or rewrite end-user coaching messages for a vendor-neutral DLP governance product.

Rules:
1. Use ONLY the allowed insert tokens listed below.
2. Never use EFF_, NS_, or any prefixed tokens.
3. Never invent new tokens.
4. Never include the exception request line in the message body — it is rendered separately.
5. Keep all wording vendor-neutral. Never mention Netskope, Purview, Forcepoint, Zscaler, Symantec.
6. Match the tone and framing to the selected control_type:
   - block: clearly state the action was blocked and the user cannot proceed.
   - coach_acknowledge: warn the user and explain they can stop or proceed.
   - coach_justification: explain that a business justification is required and will be logged.
   - monitor: keep the message minimal — no urgent language needed.
   - allow: light positive framing if any message is needed.
7. Do not blame the user. Use neutral language: "this action matched a policy" not "you violated policy".
8. Keep messages professional, clear, and suitable for enterprise employees.
9. Avoid legal overclaiming.
10. Preserve useful existing tokens unless the admin instruction says to change them.
11. Return ONLY valid JSON wrapped in <coachingSuggestion>...</coachingSuggestion> tags.

Allowed tokens:
{{APP}}, {{USER}}, {{POLICY_NAME}}, {{ACTIVITY}}, {{HOST}}, {{URL}}, {{CATEGORY}},
{{FILENAME}}, {{LABEL}}, {{DATA_TYPE}}, {{DETECTION_SOURCE}}, {{DATE_TIME}},
{{BUSINESS_JUSTIFICATION}}, {{SUPPORT_CONTACT}}, {{EXCEPTION_URL}}`

const bodySchema = z.object({
  action: z.enum([
    'draft_new', 'rewrite_existing', 'make_shorter', 'make_clearer',
    'make_stricter', 'make_softer', 'make_executive_friendly',
    'make_employee_friendly', 'add_business_justification_language',
    'convert_for_block', 'convert_for_acknowledgement', 'convert_for_justification',
  ]),
  tone:             z.enum(['neutral', 'professional', 'strict', 'friendly', 'executive', 'legal', 'security_awareness']),
  length:           z.enum(['short', 'medium', 'detailed']),
  user_instruction: z.string().max(1_000).default(''),
  current_template: z.object({
    name:                z.string().optional(),
    description:         z.string().nullable().optional(),
    control_type:        z.enum(['block', 'coach_acknowledge', 'coach_justification', 'monitor', 'allow']),
    title:               z.string().optional(),
    subtitle:            z.string().nullable().optional(),
    message:             z.string().optional(),
    show_exception_line: z.boolean().optional(),
    show_details:        z.boolean().optional(),
    recommended_for:     z.array(z.string()).optional(),
  }),
})

type ControlType = 'block' | 'coach_acknowledge' | 'coach_justification' | 'monitor' | 'allow'

function deriveControlType(action: string): ControlType | undefined {
  if (action === 'convert_for_block')           return 'block'
  if (action === 'convert_for_acknowledgement') return 'coach_acknowledge'
  if (action === 'convert_for_justification')   return 'coach_justification'
  return undefined
}

function extractTokens(text: string): string[] {
  const matches = text.match(/\{\{[A-Z_]+\}\}/g) ?? []
  return Array.from(new Set(matches))
}

function findUnsupported(text: string): string[] {
  return extractTokens(text).filter(t => !ALLOWED_TOKENS.has(t))
}

function stripBadTokens(text: string, tokens: string[]): string {
  let out = text
  for (const t of tokens) out = out.replaceAll(t, '')
  return out.replace(/  +/g, ' ').trim()
}

function extractSuggestionJson(text: string): string | null {
  const m = text.match(/<coachingSuggestion>\s*([\s\S]*?)\s*<\/coachingSuggestion>/)
  return m?.[1] ?? null
}

function buildUserPrompt(input: z.infer<typeof bodySchema>): string {
  const { action, tone, length, user_instruction, current_template: t } = input
  const lines = [`Action: ${action}`, `Tone: ${tone}`, `Length: ${length}`]
  if (user_instruction) lines.push(`Admin instruction: ${user_instruction}`)
  lines.push('', 'Current template:')
  if (t.name)        lines.push(`  Name: ${t.name}`)
  if (t.description) lines.push(`  Description: ${t.description}`)
  lines.push(`  Control type: ${t.control_type}`)
  if (t.title)    lines.push(`  Title: ${t.title}`)
  if (t.subtitle) lines.push(`  Subtitle: ${t.subtitle}`)
  if (t.message)  lines.push(`  Message: ${t.message}`)
  lines.push(`  Show exception line: ${t.show_exception_line ?? true}`)
  lines.push(`  Show details block: ${t.show_details ?? false}`)
  if (t.recommended_for?.length) lines.push(`  Recommended for: ${t.recommended_for.join(', ')}`)
  lines.push('', 'Output JSON with these fields: name, description, title, subtitle, message, recommended_for (string array).')
  lines.push('Wrap the output in <coachingSuggestion>...</coachingSuggestion> tags.')
  return lines.join('\n')
}

router.post('/', async (req, res, next) => {
  const internalSecret = config.INTERNAL_API_SECRET
  if (internalSecret && req.headers['x-effata-internal-secret'] !== internalSecret) {
    res.status(401).json({ error: 'Unauthorized' })
    return
  }

  const ctx   = req.context!
  const start = Date.now()

  const parsed = bodySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? 'Invalid request body' })
    return
  }

  const { action } = parsed.data
  const userPrompt = buildUserPrompt(parsed.data)

  let inputTokens  = 0
  let outputTokens = 0

  try {
    const firstMsg = await anthropic.messages.create({
      model:      MODEL,
      max_tokens: 2048,
      system:     SYSTEM_PROMPT,
      messages:   [{ role: 'user', content: userPrompt }],
    })

    inputTokens  += firstMsg.usage.input_tokens
    outputTokens += firstMsg.usage.output_tokens

    const firstText = firstMsg.content.find(b => b.type === 'text')?.text ?? ''
    const firstJson = extractSuggestionJson(firstText)

    if (!firstJson) {
      void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'coaching-message', runType: 'user', status: 'error', inputTokens, outputTokens, latencyMs: Date.now() - start, error: 'no suggestion tag' })
      res.status(500).json({ error: 'AI did not return a valid suggestion' })
      return
    }

    let raw: Record<string, unknown>
    try { raw = JSON.parse(firstJson) }
    catch {
      void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'coaching-message', runType: 'user', status: 'error', inputTokens, outputTokens, latencyMs: Date.now() - start, error: 'json parse failed' })
      res.status(500).json({ error: 'AI returned invalid JSON' })
      return
    }

    const existingRec = parsed.data.current_template.recommended_for ?? []

    let finalName        = String(raw.name            ?? '')
    let finalDescription = String(raw.description     ?? '')
    let finalTitle       = String(raw.title           ?? '')
    let finalSubtitle    = String(raw.subtitle        ?? '')
    let finalMessage     = String(raw.message         ?? '')
    let finalRec         = Array.isArray(raw.recommended_for) ? (raw.recommended_for as unknown[]).map(String) : existingRec

    const warnings: string[] = []
    const badFirst = findUnsupported([finalTitle, finalSubtitle, finalMessage].join(' '))

    if (badFirst.length > 0) {
      const retryMsg = await anthropic.messages.create({
        model:      MODEL,
        max_tokens: 2048,
        system:     SYSTEM_PROMPT,
        messages:   [
          { role: 'user',      content: userPrompt },
          { role: 'assistant', content: firstText },
          { role: 'user',      content: `Your output used unsupported tokens: ${badFirst.join(', ')}. Remove them and rephrase those sentences naturally — do not leave awkward gaps. Output only the corrected JSON in <coachingSuggestion>...</coachingSuggestion> tags.` },
        ],
      })

      inputTokens  += retryMsg.usage.input_tokens
      outputTokens += retryMsg.usage.output_tokens

      const retryText = retryMsg.content.find(b => b.type === 'text')?.text ?? ''
      const retryJson = extractSuggestionJson(retryText)

      if (retryJson) {
        try {
          const retried = JSON.parse(retryJson) as Record<string, unknown>
          finalName        = String(retried.name            ?? finalName)
          finalDescription = String(retried.description     ?? finalDescription)
          finalTitle       = String(retried.title           ?? finalTitle)
          finalSubtitle    = String(retried.subtitle        ?? finalSubtitle)
          finalMessage     = String(retried.message         ?? finalMessage)
          finalRec         = Array.isArray(retried.recommended_for) ? (retried.recommended_for as unknown[]).map(String) : finalRec

          const stillBad = findUnsupported([finalTitle, finalSubtitle, finalMessage].join(' '))
          if (stillBad.length > 0) {
            finalTitle    = stripBadTokens(finalTitle, stillBad)
            finalSubtitle = stripBadTokens(finalSubtitle, stillBad)
            finalMessage  = stripBadTokens(finalMessage, stillBad)
            warnings.push(...stillBad)
          }
        } catch {
          finalTitle    = stripBadTokens(finalTitle, badFirst)
          finalSubtitle = stripBadTokens(finalSubtitle, badFirst)
          finalMessage  = stripBadTokens(finalMessage, badFirst)
          warnings.push(...badFirst)
        }
      } else {
        finalTitle    = stripBadTokens(finalTitle, badFirst)
        finalSubtitle = stripBadTokens(finalSubtitle, badFirst)
        finalMessage  = stripBadTokens(finalMessage, badFirst)
        warnings.push(...badFirst)
      }
    }

    const tokens_used    = extractTokens([finalTitle, finalSubtitle, finalMessage].join(' '))
    const derived_ct     = deriveControlType(action)
    const data: Record<string, unknown> = {
      name:            finalName,
      description:     finalDescription,
      title:           finalTitle,
      subtitle:        finalSubtitle,
      message:         finalMessage,
      recommended_for: finalRec,
      tokens_used,
      warnings,
    }
    if (derived_ct !== undefined) data.control_type = derived_ct

    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'coaching-message', runType: 'user', status: 'completed', inputTokens, outputTokens, latencyMs: Date.now() - start })
    res.json({ data })
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'coaching-message', runType: 'user', status: 'error', inputTokens, outputTokens, latencyMs: Date.now() - start, error: msg })
    next(err)
  }
})

export default router
