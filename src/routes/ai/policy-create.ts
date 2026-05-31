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
    id:             z.string(),
    name:           z.string(),
    system_tag:     z.string().nullable(),
    access_posture: z.string().optional(),
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
    ? ctx.categories.map(c => {
        const posture = c.access_posture ?? (c.system_tag === 'prohibited' ? 'block' : 'allow')
        const note = posture === 'block'
          ? 'Access is BLOCKED at browse+login. Use govern_app_access intent ONLY. Do NOT add data detection policies for this category.'
          : 'Access is ALLOWED. Use data detection intents (prevent_exfiltration, detect_only, coach_user). Do NOT use govern_app_access for this category.'
        return `  - id: "${c.id}", name: "${c.name}", system_tag: ${JSON.stringify(c.system_tag)}, access_posture: "${posture}" — ${note}`
      }).join('\n')
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
    "users": ["All Users"],            // default; infer from request if a specific group is mentioned
                                        // e.g., "HR users" → ["HR"], "Finance team" → ["Finance"]
                                        // Use plain display names only. Multiple groups allowed.
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
  "exceptions": [],                    // REQUIRED when user mentions "except X", "excluding X", "exempt X", or names a specific app/group to exclude
                                      // Each entry: { "effect": "allow", "reason": "<what is exempted and why>" }
                                      // ⚠ RULE: if the user request includes ANY exclusion, you MUST populate this array — never leave it empty if an exception was stated
                                      // effect is almost always "allow" (the exception permits what the main policy blocks)
                                      // Example: "block source code upload to all GenAI, except GitHub Copilot"
                                      //   → { "effect": "allow", "reason": "GitHub Copilot is exempted — approved IDE-integrated developer workflow" }
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
  - ALWAYS prefer data_type conditions — they are the primary detection mechanism.
  - Prefer data types from the available data types list below.
  - If a matching type is not in the list, still use data_type with a descriptive name and add a warning in provenance.warnings
    (e.g. "No PCI data type in catalog — create a PCI DLP profile in Netskope using PAN regex + CVV + expiry patterns")
  - For financial/PCI data: use data_type with name "PCI / Payment Card Data", sensitivity matching the request level.
    Do NOT use regex or filenames for PCI unless the user explicitly asks.

For classification_label conditions:
  { "type": "classification_label", "label_name": "<name>", "sensitivity": "<level>" }
  ⚠ ONLY add classification_label conditions when the user EXPLICITLY mentions labels, MIP, TITUS, or "classification".
  Do NOT add them just because you think they might apply. Most policies do not need them.

For filename conditions:
  { "type": "filename", "name": "<description>", "pattern": "<glob or keyword pattern>", "sensitivity": "<level>" }
  ⚠ ONLY add filename conditions when the user EXPLICITLY mentions files, filenames, or file patterns.
  Do NOT add them based on data type inference (e.g., do NOT add "*pci*" just because the policy is about PCI data).

govern_app_access rule:
  - "govern_app_access" = app-level access decision (block / allow / restrict entry to the app itself)
  - Activities MUST be EXACTLY ["browse", "login"] — NEVER include post, prompt_submit, upload, download, response
  - content.conditions MUST be [] — no data scanning; blocked at access level before any data activity
  - content.operator must be "any"
  - ONLY use govern_app_access for categories where access_posture = "block" (currently: Prohibited only)
  - NEVER use govern_app_access for categories where access_posture = "allow" (Restricted, Approved with Conditions, Approved)
  - Use when: user wants to block/allow/restrict an app entirely (e.g. "block DeepSeek", "block prohibited AI tools", "allow Copilot for all users")

## Exceptions rule (critical)

If the user's request includes ANY exclusion — "except X", "excluding X", "not X", "exempt X", "allow X", "exclude Y":
- ALWAYS populate npj.exceptions with at least one entry describing what is excluded
- Do NOT put the exception only in the description or sourceImpact — it MUST appear in npj.exceptions
- effect: "allow" = something is permitted that the main policy would otherwise block/restrict
- reason: clear sentence naming the exempted app/group and the business justification
- Example: "Block source code upload to GenAI – Except GitHub Copilot" → exceptions: [{ "effect": "allow", "reason": "GitHub Copilot is exempted — approved IDE-integrated developer workflow for engineers" }]

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

  // Normalize govern_app_access before validation — AI sometimes generates wrong activities.
  // This is a domain rule, not a validation error: force browse+login and clear conditions.
  if (proposalObj && typeof proposalObj === 'object') {
    const p = proposalObj as Record<string, unknown>
    const npj = p.npj as Record<string, unknown> | undefined
    if (npj) {
      const scope = (npj.scope ?? {}) as Record<string, unknown>
      // Default users to All Users if not specified
      if (!Array.isArray(scope.users) || (scope.users as unknown[]).length === 0) {
        scope.users = ['All Users']
      }
      npj.scope = scope
      if (npj.intent === 'govern_app_access') {
        scope.activities = ['browse', 'login']
        const content = (npj.content ?? {}) as Record<string, unknown>
        content.conditions = []
        npj.content = content
      }
    }
  }

  // Serialize normalized object so repair prompt receives already-correct activities/conditions.
  const normalizedJson = JSON.stringify(proposalObj)

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
      messages:   [{ role: 'user', content: buildRepairPrompt(normalizedJson, validation.errors) }],
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

    if (repairedObj !== undefined) {
      // Apply the same normalization to the repaired object as we did to the original.
      if (typeof repairedObj === 'object' && repairedObj !== null) {
        const rp   = repairedObj as Record<string, unknown>
        const rNpj = rp.npj as Record<string, unknown> | undefined
        if (rNpj) {
          const rScope = (rNpj.scope ?? {}) as Record<string, unknown>
          if (!Array.isArray(rScope.users) || (rScope.users as unknown[]).length === 0) {
            rScope.users = ['All Users']
          }
          rNpj.scope = rScope
          if (rNpj.intent === 'govern_app_access') {
            const rContent = (rNpj.content ?? {}) as Record<string, unknown>
            rScope.activities   = ['browse', 'login']
            rContent.conditions = []
            rNpj.content        = rContent
          }
        }
      }

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
