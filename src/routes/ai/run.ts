import { Router } from 'express'
import { z } from 'zod'
import { logAiRun } from '../../lib/ai-log'
import { generateRegex } from '../../ai/agents/regex'
import { generateTestData } from '../../ai/agents/test-data'
import { generateTestFile } from '../../ai/agents/test-file'
import { evidenceChat } from '../../ai/agents/evidence'
import { researchApp, identifyApp, discoverNewApps } from '../../ai/agents/genai-research'
import { suggestClassifications } from '../../ai/agents/classify'
import { reviewDlpTool } from '../../ai/agents/tool-review'

const router = Router()

// ── Per-agent Zod payload schemas ─────────────────────────────────────────────

const messageSchema = z.object({
  role:    z.enum(['user', 'assistant']),
  content: z.string().max(10_000),
})

const AGENT_SCHEMAS = {
  'regex': z.object({
    prompt: z.string().min(1).max(500),
  }),
  'test-data': z.object({
    prompt:   z.string().min(1).max(1_000),
    rowCount: z.number().int().min(1).max(50),
  }),
  'test-file': z.object({
    prompt: z.string().min(1).max(1_000),
  }),
  'evidence': z.object({
    messages: z.array(messageSchema).min(1).max(20),
  }),
  'genai-research': z.object({
    app: z.object({
      app_id:   z.string(),
      app_name: z.string(),
      vendor:   z.string(),
      domain:   z.string(),
      app_type: z.string(),
    }),
  }),
  'genai-identify': z.object({
    searchTerm: z.string().min(1).max(200),
  }),
  'genai-discover': z.object({
    existingAppIds: z.array(z.string()).max(500),
  }),
  'classify': z.object({
    dataTypes: z.array(z.object({ id: z.string(), name: z.string(), examples: z.array(z.string()).optional(), notes: z.string().optional() })).min(1).max(100),
    labels:    z.array(z.object({ id: z.string(), name: z.string(), description: z.string().optional(), priority: z.number() })).min(1).max(20),
  }),
  'tool-review': z.object({
    toolName: z.string().min(1).max(200),
  }),
} as const

type AgentKey = keyof typeof AGENT_SCHEMAS

// ── Dispatcher ────────────────────────────────────────────────────────────────

const requestSchema = z.object({
  agent:   z.string(),
  payload: z.unknown(),
})

router.post('/', async (req, res, next) => {
  const ctx = req.context!
  const start = Date.now()

  const parsed = requestSchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? 'Invalid request body' })
    return
  }

  const { agent, payload } = parsed.data

  if (!(agent in AGENT_SCHEMAS)) {
    res.status(422).json({ error: `Unknown agent: ${agent}` })
    return
  }

  const schema = AGENT_SCHEMAS[agent as AgentKey]
  const payloadParsed = schema.safeParse(payload)
  if (!payloadParsed.success) {
    res.status(400).json({ error: payloadParsed.error.errors[0]?.message ?? 'Invalid payload' })
    return
  }

  try {
    let result: unknown
    let inputTokens  = 0
    let outputTokens = 0

    const p = payloadParsed.data as Record<string, unknown>

    switch (agent as AgentKey) {
      case 'regex': {
        const r = await generateRegex(p.prompt as string)
        result = r.result; inputTokens = r.inputTokens; outputTokens = r.outputTokens
        break
      }
      case 'test-data': {
        const r = await generateTestData(p.prompt as string, p.rowCount as number)
        result = r.result; inputTokens = r.inputTokens; outputTokens = r.outputTokens
        break
      }
      case 'test-file': {
        const r = await generateTestFile(p.prompt as string)
        result = r.result; inputTokens = r.inputTokens; outputTokens = r.outputTokens
        break
      }
      case 'evidence': {
        const r = await evidenceChat(p.messages as Array<{ role: 'user' | 'assistant'; content: string }>)
        result = r.result; inputTokens = r.inputTokens; outputTokens = r.outputTokens
        break
      }
      case 'genai-research': {
        const r = await researchApp(p.app as Parameters<typeof researchApp>[0])
        result = r.result; inputTokens = r.inputTokens; outputTokens = r.outputTokens
        break
      }
      case 'genai-identify': {
        const r = await identifyApp(p.searchTerm as string)
        result = r.result; inputTokens = r.inputTokens; outputTokens = r.outputTokens
        break
      }
      case 'genai-discover': {
        const r = await discoverNewApps(p.existingAppIds as string[])
        result = r.result; inputTokens = r.inputTokens; outputTokens = r.outputTokens
        break
      }
      case 'classify': {
        const r = await suggestClassifications(
          p.dataTypes as Parameters<typeof suggestClassifications>[0],
          p.labels    as Parameters<typeof suggestClassifications>[1],
        )
        result = r.result; inputTokens = r.inputTokens; outputTokens = r.outputTokens
        break
      }
      case 'tool-review': {
        const r = await reviewDlpTool(p.toolName as string)
        result = r.result; inputTokens = r.inputTokens; outputTokens = r.outputTokens
        break
      }
    }

    const latencyMs = Date.now() - start
    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent, runType: 'user', status: 'completed', inputTokens, outputTokens, latencyMs })

    res.json({ result })
  } catch (err) {
    const latencyMs = Date.now() - start
    const message   = err instanceof Error ? err.message : String(err)
    const status    = message.includes('timed out') || (err instanceof Error && err.name === 'AbortError') ? 'timeout' : 'error'

    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent, runType: 'user', status, inputTokens: 0, outputTokens: 0, latencyMs, error: message })
    next(err)
  }
})

export default router
