import { serviceClient } from './supabase'
import { MODEL } from './anthropic'

export interface AiRunOpts {
  orgId:        string
  userId:       string | null
  agent:        string
  runType:      'user' | 'cron'
  status:       'completed' | 'error' | 'timeout'
  inputTokens:  number
  outputTokens: number
  latencyMs:    number
  error?:       string
}

const INPUT_COST_PER_MTK  = 0.000003   // $3 per 1M input tokens
const OUTPUT_COST_PER_MTK = 0.000015   // $15 per 1M output tokens

export async function logAiRun(opts: AiRunOpts): Promise<void> {
  const costEstimate =
    opts.inputTokens * INPUT_COST_PER_MTK +
    opts.outputTokens * OUTPUT_COST_PER_MTK

  try {
    await serviceClient.from('ai_runs').insert({
      org_id:        opts.orgId,
      user_id:       opts.userId,
      agent:         opts.agent,
      run_type:      opts.runType,
      status:        opts.status,
      model:         MODEL,
      input_tokens:  opts.inputTokens,
      output_tokens: opts.outputTokens,
      latency_ms:    opts.latencyMs,
      cost_estimate: parseFloat(costEstimate.toFixed(6)),
      error:         opts.error ?? null,
      created_at:    new Date().toISOString(),
    })
  } catch {
    // Fire-and-forget — never block AI response on log failure
  }
}
