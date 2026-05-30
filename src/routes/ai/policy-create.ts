import { Router } from 'express'
import { z } from 'zod'
import { anthropic, MODEL } from '../../lib/anthropic'
import { logAiRun } from '../../lib/ai-log'
import { logAuditEvent } from '../../lib/audit-log'
import { validatePolicyProposal } from '../../lib/npj-schema'

const router = Router()

const contextSchema = z.object({
  intents:    z.array(z.string()).optional(),
  categories: z.array(z.object({
    id:         z.string(),
    name:       z.string(),
    system_tag: z.string().nullable(),
  })).optional(),
  dataTypes: z.array(z.object({
    key:         z.string(),
    name:        z.string(),
    sensitivity: z.string(),
  })).optional(),
  actions:    z.array(z.string()).optional(),
  activities: z.array(z.string()).optional(),
  vendors:    z.array(z.string()).optional(),
})

const bodySchema = z.object({
  message: z.string().min(1).max(5_000),
  context: contextSchema.optional(),
})

type PolicyContext = z.infer<typeof contextSchema>

const DEFAULT_CONTEXT: Required<PolicyContext> = {
  intents:    ['prevent_exfiltration','detect_only','coach_user','allow_approved_use','govern_app_access','label_or_classify','govern_data_at_rest'],
  categories: [],
  dataTypes:  [],
  actions:    ['allow','monitor','alert','coach','block'],
  activities: ['browse','post','prompt_submit','upload','download','response'],
  vendors:    [],
}

function buildSystemPrompt(ctx: Required<PolicyContext>): string {
  const intentsBlock    = ctx.intents.map(i => `  - ${i}`).join('\n')
  const actionsBlock    = ctx.actions.join(', ')
  const activitiesBlock = ctx.activities.join(', ')

  const categoriesBlock = ctx.categories.length
    ? ctx.categories.map(c => `  - id: "${c.id}", name: "${c.name}", system_tag: ${JSON.stringify(c.system_tag)}`).join('\n')
    : '  (none configured — leave scope.app_categories as [])'

  const dataTypesBlock = ctx.dataTypes.length
    ? ctx.dataTypes.map(d => `  - key: "${d.key}", name: "${d.name}", sensitivity: "${d.sensitivity}"`).join('\n')
    : '  (none configured — use generic sensitivity values)'

  const vendorBlock = ctx.vendors.length
    ? ctx.vendors.map(v => `  - ${v}`).join('\n')
    : '  (none configured — provide generic translation guidance)'

  return `You are a senior DLP policy designer for GenAI security. Given a plain-language policy requirement, generate a complete structured policy proposal.

## Output format

First write 2–3 sentences explaining the policy proposal and key design decisions.

Then output a single JSON block wrapped EXACTLY like this (no trailing text after the closing tag):
<policyProposal>
{ ...valid JSON... }
</policyProposal>

## PolicyProposal JSON structure (required fields)

{
  "name": string,           // concise policy name
  "description": string,    // 1–2 sentences
  "npj": { ...see below... },
  "sourceImpact": [{ "source_layer": string, "impact": string, "action_required": boolean }],
  "translationImpact": [{ "vendor_id": string, "impact": string, "requires_translation": boolean }]
}

## NPJ structure and constraints

\`\`\`
npj = {
  "schema_version": "1.0",            // REQUIRED, always "1.0"
  "intent": <one of the valid intents below>,
  "policy_family": string,
  "scope": {
    "activities": [<canonical activity keys only>],
    "channels": ["genai"],             // ALWAYS ["genai"] — Effata GenAI channel
    "app_categories": [{ "id": "...", "system_tag": "...", "name": "..." }]
                                       // use only IDs from the available categories
  },
  "content": {
    "operator": "any" | "all",         // NOT "OR" or "AND" — must be "any" or "all"
    "conditions": [...]                // see condition types below
                                       // MUST be [] when intent is "govern_app_access"
  },
  "decision": {
    "mode": <one of the 5 valid modes below>,
    "severity": "low" | "medium" | "high" | "critical",
    "require_acknowledgement": boolean,
    "require_justification": boolean,
    "preserve_evidence": boolean,
    "create_incident": boolean
  },
  "exceptions": [],                    // usually empty unless explicitly needed
  "provenance": {
    "generated_from": "ai-assisted",   // ALWAYS "ai-assisted"
    "source_model": "ai-policy-assistant",
    "generated_at": "<ISO timestamp>",
    "compiler_version": "1.0.0",
    "warnings": []                     // add warnings about missing data types etc.
  }
}
\`\`\`

## Valid intents (pick exactly one)
${intentsBlock}

## Valid decision.mode values (pick exactly one)
  allow    — permit the action without restriction
  monitor  — log silently, no user notification
  alert    — log and notify the security team, no user disruption
  coach    — SOFT control: show a guidance message; user CAN still proceed after acknowledging
  block    — HARD control: action is completely prevented; user CANNOT bypass

  ⚠ CRITICAL distinction:
  - "block" = hard stop, no bypass. Use this when the user says "block", "prevent", "deny", "prohibit".
  - "coach" = soft nudge, user can proceed. Use ONLY when the request explicitly asks for a warning or guidance WITHOUT a hard stop.
  - "block with a coaching message" → mode "block" (NOT "coach"). Block mode can still display a message to the user.
  - Do NOT use "coach" when the user intent is to prevent the action entirely.

  ⚠ NEVER use "coach-ack" or "coach-just" in decision.mode.
  For coach with acknowledgement: use mode "coach" + require_acknowledgement: true
  For coach with justification:   use mode "coach" + require_acknowledgement: true + require_justification: true

## Valid activity keys (use only these)
  ${activitiesBlock}

## Condition types (data_type | classification_label | filename)

For data_type conditions:
  { "type": "data_type", "sensitivity": "<sensitivity>", "name": "<human name>", "confidence": "high" | "medium" }
  - Prefer data types from the available data types list below
  - If user requests a data type not in the list, include it but add a warning in provenance.warnings

For classification_label conditions (MIP, TITUS, custom labels):
  { "type": "classification_label", "label_name": "<name>", "sensitivity": "<level>" }

For filename conditions:
  { "type": "filename", "name": "<description>", "pattern": "<glob or keyword pattern>", "sensitivity": "<level>" }

govern_app_access rule: when intent is "govern_app_access", content.conditions MUST be [] and content.operator must be "any".

## Available categories (use only these IDs in scope.app_categories)
${categoriesBlock}

## Available data types (prefer these for data_type conditions)
${dataTypesBlock}

## Connected vendors (tailor translationImpact to these)
${vendorBlock}

## sourceImpact guidance
Use source_layer values: manual_policy | control_matrix | data_catalog | app_governance | customer_labels
Describe how this policy relates to existing governance layers.

## translationImpact guidance
One entry per vendor from the connected vendors list. If no vendors, provide one generic entry with vendor_id omitted.
Be specific: which activities, profiles, or capabilities require implementation.
`
}

function extractProposalJson(text: string): string | null {
  const match = text.match(/<policyProposal>\s*([\s\S]*?)\s*<\/policyProposal>/)
  return match?.[1] ?? null
}

function buildRepairPrompt(originalJson: string, errors: string[]): string {
  return `The following PolicyProposal JSON failed validation with these errors:

${errors.map(e => `  - ${e}`).join('\n')}

Fix ONLY what is needed to resolve the errors. Keep the business intent unchanged.

Output the full, corrected PolicyProposal JSON object only — no explanation, no markdown fences, no <policyProposal> tags.

The JSON must include all five top-level fields: name, description, npj, sourceImpact, translationImpact.

Original JSON:
${originalJson}`
}

router.post('/', async (req, res, next) => {
  const ctx   = req.context!
  const start = Date.now()

  const parsed = bodySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? 'Invalid request body' })
    return
  }

  const { message, context } = parsed.data

  // Merge with defaults; cap dataTypes to prevent oversized prompts
  const mergedCtx: Required<PolicyContext> = {
    intents:    context?.intents    ?? DEFAULT_CONTEXT.intents,
    categories: context?.categories ?? DEFAULT_CONTEXT.categories,
    dataTypes:  (context?.dataTypes ?? DEFAULT_CONTEXT.dataTypes).slice(0, 50),
    actions:    context?.actions    ?? DEFAULT_CONTEXT.actions,
    activities: context?.activities ?? DEFAULT_CONTEXT.activities,
    vendors:    context?.vendors    ?? DEFAULT_CONTEXT.vendors,
  }

  void logAuditEvent({
    action:     'policy.ai_create_request',
    orgId:      ctx.orgId,
    userId:     ctx.userId,
    entityType: 'org_genai_policies',
    details:    { prompt_length: message.length, vendors: mergedCtx.vendors },
  })

  res.setHeader('Content-Type', 'text/plain; charset=utf-8')
  res.setHeader('Transfer-Encoding', 'chunked')
  res.setHeader('Cache-Control', 'no-cache')
  res.flushHeaders()

  let inputTokens  = 0
  let outputTokens = 0
  let fullText     = ''

  try {
    const stream = anthropic.messages.stream({
      model:      MODEL,
      max_tokens: 4096,
      system:     buildSystemPrompt(mergedCtx),
      messages:   [{ role: 'user', content: message }],
    })

    for await (const chunk of stream) {
      if (chunk.type === 'content_block_delta' && chunk.delta.type === 'text_delta') {
        fullText += chunk.delta.text
        res.write(chunk.delta.text)
      }
    }

    const finalMsg = await stream.finalMessage()
    inputTokens  = finalMsg.usage.input_tokens
    outputTokens = finalMsg.usage.output_tokens

  } catch (err) {
    const msg    = err instanceof Error ? err.message : String(err)
    const status = msg.includes('timed out') || (err instanceof Error && err.name === 'AbortError') ? 'timeout' : 'error'
    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'policy-create', runType: 'user', status, inputTokens: 0, outputTokens: 0, latencyMs: Date.now() - start, error: msg })
    if (!res.headersSent) next(err)
    else res.end()
    return
  }

  // ── Post-stream validation + optional repair ────────────────────────────────

  const rawJson = extractProposalJson(fullText)

  if (!rawJson) {
    // No <policyProposal> tag — frontend will show a parse error
    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'policy-create', runType: 'user', status: 'completed', inputTokens, outputTokens, latencyMs: Date.now() - start })
    res.end()
    return
  }

  let proposalObj: unknown
  try { proposalObj = JSON.parse(rawJson) } catch {
    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'policy-create', runType: 'user', status: 'error', inputTokens, outputTokens, latencyMs: Date.now() - start, error: 'proposal JSON parse failed' })
    res.end()
    return
  }

  const validation = validatePolicyProposal(proposalObj)
  if (validation.valid) {
    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'policy-create', runType: 'user', status: 'completed', inputTokens, outputTokens, latencyMs: Date.now() - start })
    res.end()
    return
  }

  // ── Repair attempt ──────────────────────────────────────────────────────────

  let repairInputTokens  = 0
  let repairOutputTokens = 0
  let repaired           = false

  try {
    const repairMsg = await anthropic.messages.create({
      model:      MODEL,
      max_tokens: 2048,
      messages:   [{ role: 'user', content: buildRepairPrompt(rawJson, validation.errors) }],
    })

    repairInputTokens  = repairMsg.usage.input_tokens
    repairOutputTokens = repairMsg.usage.output_tokens

    const repairText = repairMsg.content.find(b => b.type === 'text')?.text ?? ''

    // Strip any accidental markdown fences the model might add
    const cleanedRepair = repairText.replace(/^```(?:json)?\s*/i, '').replace(/\s*```\s*$/, '').trim()

    let repairedObj: unknown
    try { repairedObj = JSON.parse(cleanedRepair) } catch {
      // Repair produced invalid JSON — fall through to error
    }

    if (repairedObj) {
      const repairValidation = validatePolicyProposal(repairedObj)
      if (repairValidation.valid) {
        res.write(`<policyProposalRepair>${JSON.stringify(repairedObj)}</policyProposalRepair>`)
        repaired = true
      } else {
        res.write(`<policyProposalError>${JSON.stringify({ errors: repairValidation.errors })}</policyProposalError>`)
      }
    } else {
      res.write(`<policyProposalError>${JSON.stringify({ errors: validation.errors })}</policyProposalError>`)
    }
  } catch {
    res.write(`<policyProposalError>${JSON.stringify({ errors: validation.errors })}</policyProposalError>`)
  }

  void logAiRun({
    orgId:        ctx.orgId,
    userId:       ctx.userId,
    agent:        'policy-create',
    runType:      'user',
    status:       'completed',
    inputTokens:  inputTokens + repairInputTokens,
    outputTokens: outputTokens + repairOutputTokens,
    latencyMs:    Date.now() - start,
    error:        repaired ? undefined : `repair failed: ${validation.errors.join('; ')}`,
  })

  res.end()
})

export default router
