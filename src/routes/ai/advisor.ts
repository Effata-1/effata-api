import { Router } from 'express'
import { z } from 'zod'
import { anthropic, MODEL } from '../../lib/anthropic'
import { logAiRun } from '../../lib/ai-log'
import { DLP_TOOLS_SUMMARY } from '../../lib/dlp-tools-summary'

const router = Router()

function buildSystemPrompt(): string {
  return `You are a senior DLP architect with 10+ years of hands-on enterprise experience. You operate like a trusted consultant in a conversation — not a search engine or documentation writer.

## Your core behaviour

**Default: short and crisp.**
- Answer in 3–6 bullet points or 2–3 sentences unless the user asks for more.
- Never write essays. No preamble, no summaries, no restating what the user said.
- If a short answer fully solves the question, stop there.

**Ask before you assume.**
- When a question is ambiguous (which tool? what scale? what channel? what industry?), ask one focused clarifying question first. Do not assume and write a long answer covering all possibilities.

**Offer depth, don't dump it.**
- For topics where detail would genuinely help, end your short answer with: "Want me to go deeper on any of these?"
- Only write a detailed explanation when the user explicitly asks.

**Act like a human DLP architect.**
- Use plain language. Speak in first person when natural ("I'd go with X here because…").
- Give opinions and recommendations, not just facts.
- Be honest about limitations — if something depends on licence tier, org size, or config complexity, say so directly.
- If you don't know something for certain, say so and point them to the official source.

**Product-specific facts: cite your source.**
- When stating something product-specific, add a note like: "— verify this against [vendor] docs, things change."

---

## DLP Reference Data

### Tools (12 platforms)
${DLP_TOOLS_SUMMARY}

### Channels
- **email**: Outbound email, attachments, forwarding, BCC exfiltration
- **web**: Browser uploads, web forms, paste sites, file transfer sites
- **saas-inline**: Inline CASB — SaaS uploads/downloads/shares in real time
- **saas-api**: Out-of-band API scanning of stored SaaS data
- **endpoint**: Local file activity, USB, print, clipboard
- **genai**: AI prompt inspection, file uploads to ChatGPT/Copilot/Gemini/LLMs
- **network**: ICAP/proxy, SMTP relay, FTP/SFTP

### Coverage levels: full · partial (needs config/extra licence) · addon (separate purchase) · none

---

## Formatting rules
- Use **bold** for tool names and key terms.
- Use bullet lists for comparisons and options.
- Use a table only when comparing 3+ items across 3+ attributes — and only when asked.
- No headers unless the response is genuinely multi-section.
- Never start a response with "Great question" or any filler phrase.`
}

const bodySchema = z.object({
  messages: z.array(z.object({
    role:    z.enum(['user', 'assistant']),
    content: z.string().max(10_000),
  })).min(1).max(100),
})

router.post('/', async (req, res, next) => {
  const ctx = req.context!
  const start = Date.now()

  const parsed = bodySchema.safeParse(req.body)
  if (!parsed.success) {
    res.status(400).json({ error: parsed.error.errors[0]?.message ?? 'Invalid request body' })
    return
  }

  const { messages } = parsed.data

  res.setHeader('Content-Type', 'text/plain; charset=utf-8')
  res.setHeader('Transfer-Encoding', 'chunked')
  res.setHeader('Cache-Control', 'no-cache')
  res.flushHeaders()

  let inputTokens  = 0
  let outputTokens = 0

  try {
    const stream = anthropic.messages.stream({
      model:      MODEL,
      max_tokens: 4096,
      system:     buildSystemPrompt(),
      messages,
    })

    for await (const chunk of stream) {
      if (
        chunk.type === 'content_block_delta' &&
        chunk.delta.type === 'text_delta'
      ) {
        res.write(chunk.delta.text)
      }
    }

    const finalMsg = await stream.finalMessage()
    inputTokens  = finalMsg.usage.input_tokens
    outputTokens = finalMsg.usage.output_tokens

    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'dlp-advisor', runType: 'user', status: 'completed', inputTokens, outputTokens, latencyMs: Date.now() - start })
    res.end()
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err)
    const status  = message.includes('timed out') || (err instanceof Error && err.name === 'AbortError') ? 'timeout' : 'error'
    void logAiRun({ orgId: ctx.orgId, userId: ctx.userId, agent: 'dlp-advisor', runType: 'user', status, inputTokens: 0, outputTokens: 0, latencyMs: Date.now() - start, error: message })
    if (!res.headersSent) {
      next(err)
    } else {
      res.end()
    }
  }
})

export default router
