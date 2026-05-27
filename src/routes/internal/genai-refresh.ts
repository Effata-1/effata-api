import { Router } from 'express'
import { serviceClient } from '../../lib/supabase'
import { logAuditEvent } from '../../lib/audit-log'

const SYSTEM_ORG = '00000000-0000-0000-0000-000000000000'

const router = Router()

router.post('/', async (_req, res, next) => {
  try {
    // Dedup: skip if a genai-refresh job is already pending or running
    const { count, error: countErr } = await serviceClient
      .from('ai_jobs')
      .select('id', { count: 'exact', head: true })
      .in('status', ['pending', 'running'])
      .eq('job_type', 'genai-refresh')

    if (countErr) return next(countErr)

    if ((count ?? 0) > 0) {
      return res.json({ status: 'already_running' })
    }

    const { error } = await serviceClient.from('ai_jobs').insert({
      org_id:   SYSTEM_ORG,
      job_type: 'genai-refresh',
      payload:  {},
    })

    if (error) return next(error)

    void logAuditEvent({
      action:  'job.created',
      orgId:   SYSTEM_ORG,
      userId:  null,
      details: { job_type: 'genai-refresh', run_type: 'cron', source: 'railway' },
    })

    res.json({ status: 'queued' })
  } catch (err) {
    next(err)
  }
})

export default router
