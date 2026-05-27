import { Router } from 'express'
import { z } from 'zod'
import { serviceClient } from '../../lib/supabase'
import { logAuditEvent } from '../../lib/audit-log'
import { JOB_CONFIG, isJobType } from '../../worker/job-config'
import { checkRoleLevel } from '../../middleware/rbac'

const router = Router()

const jobSchema = z.object({
  jobType: z.string(),
  payload: z.record(z.unknown()).default({}),
})

router.post('/', async (req, res, next) => {
  try {
    const parsed = jobSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors[0]?.message ?? 'Invalid input' })
    }

    const { jobType, payload } = parsed.data
    const { orgId, userId } = req.context!

    if (!isJobType(jobType)) {
      return res.status(400).json({ error: `Unknown job type: ${jobType}` })
    }

    const cfg = JOB_CONFIG[jobType]

    const allowed = await checkRoleLevel(userId, orgId, cfg.minRole)
    if (!allowed) {
      return res.status(403).json({ error: 'Insufficient permissions' })
    }

    // genai-refresh is a global singleton — no two can run concurrently
    if (jobType === 'genai-refresh') {
      const { data: existing, error: dedupErr } = await serviceClient
        .from('ai_jobs')
        .select('id')
        .in('status', ['pending', 'running'])
        .eq('job_type', 'genai-refresh')
        .limit(1)
        .maybeSingle()

      if (dedupErr) return next(dedupErr)

      if (existing) {
        return res.json({ jobId: existing.id, deduplicated: true })
      }
    }

    const { data, error } = await serviceClient
      .from('ai_jobs')
      .insert({ org_id: orgId, user_id: userId, job_type: jobType, payload })
      .select('id')
      .single()

    if (error) return next(error)

    void logAuditEvent({
      action:     'job.created',
      orgId,
      userId,
      entityType: 'ai_job',
      entityId:   data.id,
      details:    { job_type: jobType },
    })

    res.json({ jobId: data.id })
  } catch (err) {
    next(err)
  }
})

router.get('/:id', async (req, res, next) => {
  try {
    const { data, error } = await serviceClient
      .from('ai_jobs')
      .select('id, status, result, error, total_items, processed_items, created_at, completed_at')
      .eq('id', req.params.id)
      .eq('org_id', req.context!.orgId)
      .single()

    if (error) return next(error)
    res.json(data)
  } catch (err) {
    next(err)
  }
})

export default router
