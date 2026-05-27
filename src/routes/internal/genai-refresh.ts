import { Router } from 'express'
import { serviceClient } from '../../lib/supabase'
import { logAuditEvent } from '../../lib/audit-log'

const SYSTEM_ORG = '00000000-0000-0000-0000-000000000000'

const router = Router()

router.post('/', async (_req, res, next) => {
  try {
    const result = await serviceClient.functions.invoke('genai-refresh')

    if (result.error) return next(result.error)

    void logAuditEvent({
      action:  'genai_refresh.triggered',
      orgId:   SYSTEM_ORG,
      userId:  null,
      details: { run_type: 'cron', source: 'railway' },
    })

    res.json({ status: 'ok', ...result.data })
  } catch (err) {
    next(err)
  }
})

export default router
