import { Router } from 'express'
import { runComplianceCheck } from '../../ai/agents/compliance'
import { logAiRun } from '../../lib/ai-log'

const router = Router()

router.post('/', async (_req, res, next) => {
  const start = Date.now()
  try {
    const result = await runComplianceCheck()
    void logAiRun({
      orgId:        '00000000-0000-0000-0000-000000000000',
      userId:       null,
      agent:        'compliance-check',
      runType:      'cron',
      status:       'completed',
      inputTokens:  0,
      outputTokens: 0,
      latencyMs:    Date.now() - start,
    })
    res.json({ status: 'completed', ...result })
  } catch (err) {
    const latencyMs = Date.now() - start
    void logAiRun({
      orgId:        '00000000-0000-0000-0000-000000000000',
      userId:       null,
      agent:        'compliance-check',
      runType:      'cron',
      status:       'error',
      inputTokens:  0,
      outputTokens: 0,
      latencyMs,
      error:        err instanceof Error ? err.message : String(err),
    })
    next(err)
  }
})

export default router
