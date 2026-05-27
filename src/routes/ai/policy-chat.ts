import { Router } from 'express'
import { z } from 'zod'
import { anthropic, MODEL } from '../../lib/anthropic'
import { serviceClient } from '../../lib/supabase'
import { logAiRun } from '../../lib/ai-log'
import { logAuditEvent } from '../../lib/audit-log'

const router = Router()

const bodySchema = z.object({
  messages: z.array(z.object({
    role:    z.enum(['user', 'assistant']),
    content: z.string().max(20_000),
  })).min(1).max(200),
  policyId: z.string().uuid().optional(),
})

type PolicyRow = { id: string; name: string; description: string | null; policy_type: string; primary_action: string | null; approval_status: string }

function buildSystemPrompt(policies: PolicyRow[], policyId?: string): string {
  const target  = policyId ? policies.find(p => p.id === policyId) : null
  const scope   = target
    ? `You are reviewing a specific policy: "${target.name}" (${target.policy_type}, status: ${target.approval_status}).`
    : `You are reviewing all ${policies.length} GenAI DLP policies for this organisation.`

  const policySummary = policies
    .map(p => `- [${p.id}] ${p.name} | type: ${p.policy_type} | action: ${p.primary_action ?? 'none'} | status: ${p.approval_status}`)
    .join('\n')

  return `You are a senior DLP policy advisor helping an organisation refine their GenAI DLP policies.

${scope}

## Current Policy Library
${policySummary || 'No policies defined yet.'}

## Your behaviour
- Be concise and practical
- When you suggest a specific change to an existing DRAFT policy, end your message with a JSON block in this exact format:
  <policyDiff>
  { "policyId": "<uuid>", "changes": { "field": "value" } }
  </policyDiff>
- Only include fields that should change. Never include id, org_id, approval_status, or created_at.
- NEVER suggest edits to approved policies — recommend creating a new draft copy instead.
- For entirely new policy suggestions, describe in plain text only — do not output a policyDiff.
- Valid policy_type values: usage | data-handling | approved-use | prohibited
- Valid primary_action values: allow | monitor | alert | coach | coach-ack | coach-just | block`
}

async function persistMessage(
  orgId: string,
  userId: string | null,
  policyId: string | undefined,
  message: { role: string; content: string },
): Promise<void> {
  const now = new Date().toISOString()
  const entry = { ...message, created_at: now }

  let query = serviceClient
    .from('genai_policy_chats')
    .select('id, messages')
    .eq('org_id', orgId)

  if (policyId) {
    query = query.eq('policy_id', policyId) as typeof query
  } else {
    query = query.is('policy_id', null) as typeof query
  }

  const { data: existing } = await (query as ReturnType<typeof query.limit>).limit(1).maybeSingle()
  const prior = (existing?.messages as typeof entry[] | null) ?? []

  if (existing?.id) {
    await serviceClient
      .from('genai_policy_chats')
      .update({ messages: [...prior, entry], updated_at: now })
      .eq('id', existing.id)
  } else {
    await serviceClient
      .from('genai_policy_chats')
      .insert({ org_id: orgId, user_id: userId, policy_id: policyId ?? null, messages: [entry] })
  }
}

router.post('/', async (req, res, next) => {
  const ctx   = req.context!
  const start = Date.now()

  const parsed = bodySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? 'Invalid request body' })
    return
  }

  const { messages, policyId } = parsed.data

  // Fetch current org policies for context
  const { data: policies } = await serviceClient
    .from('org_genai_policies')
    .select('id, name, description, policy_type, primary_action, approval_status')
    .eq('org_id', ctx.orgId)
    .order('priority')

  const policyList = (policies ?? []) as PolicyRow[]

  // Persist user message
  const userMsg = messages[messages.length - 1]
  if (userMsg?.role === 'user') {
    void persistMessage(ctx.orgId, ctx.userId, policyId, { role: 'user', content: userMsg.content })
  }

  void logAuditEvent({
    action:     'policy_chat.message',
    orgId:      ctx.orgId,
    userId:     ctx.userId,
    entityType: 'genai_policy_chat',
    entityId:   policyId ?? undefined,
    details:    { policy_id: policyId ?? null },
  })

  res.setHeader('Content-Type', 'text/plain; charset=utf-8')
  res.setHeader('Transfer-Encoding', 'chunked')
  res.setHeader('Cache-Control', 'no-cache')
  res.flushHeaders()

  let inputTokens  = 0
  let outputTokens = 0
  let assistantText = ''

  try {
    const stream = anthropic.messages.stream({
      model:      MODEL,
      max_tokens: 4096,
      system:     buildSystemPrompt(policyList, policyId),
      messages,
    })

    for await (const chunk of stream) {
      if (chunk.type === 'content_block_delta' && chunk.delta.type === 'text_delta') {
        assistantText += chunk.delta.text
        res.write(chunk.delta.text)
      }
    }

    const finalMsg = await stream.finalMessage()
    inputTokens  = finalMsg.usage.input_tokens
    outputTokens = finalMsg.usage.output_tokens

    if (assistantText) {
      void persistMessage(ctx.orgId, ctx.userId, policyId, { role: 'assistant', content: assistantText })
    }

    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'policy-chat', runType: 'user', status: 'completed', inputTokens, outputTokens, latencyMs: Date.now() - start })
    res.end()
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    const status  = message.includes('timed out') || (err instanceof Error && err.name === 'AbortError') ? 'timeout' : 'error'
    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'policy-chat', runType: 'user', status, inputTokens: 0, outputTokens: 0, latencyMs: Date.now() - start, error: message })
    if (!res.headersSent) next(err)
    else res.end()
  }
})

export default router
