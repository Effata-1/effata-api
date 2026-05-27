import { Router } from 'express'
import { requireRole } from '../../middleware/rbac'
import { serviceClient } from '../../lib/supabase'
import { logAuditEvent } from '../../lib/audit-log'

const router = Router()

router.post('/', requireRole('analyst'), async (req, res, next) => {
  try {
    const { orgId, userId } = req.context!

    const { data, error } = await serviceClient
      .from('ai_jobs')
      .insert({ org_id: orgId, user_id: userId, job_type: 'coverage-review', payload: { orgId } })
      .select('id')
      .single()

    if (error) return next(error)

    void logAuditEvent({
      action:     'job.created',
      orgId,
      userId,
      entityType: 'ai_job',
      entityId:   data.id,
      details:    { job_type: 'coverage-review', source: 'user' },
    })

    res.json({ ok: true, jobId: data.id })
  } catch (err) {
    next(err)
  }
})

export default router
