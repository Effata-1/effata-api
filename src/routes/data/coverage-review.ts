import { Router } from 'express'
import { requireRole } from '../../middleware/rbac'
import { serviceClient } from '../../lib/supabase'
import { logAuditEvent } from '../../lib/audit-log'

const router = Router()

router.post('/', requireRole('analyst'), async (req, res, next) => {
  try {
    const { orgId, userId } = req.context!

    const result = await serviceClient.functions.invoke('review-dlp-coverage', {
      body: { orgId },
    })

    if (result.error) return next(result.error)

    void logAuditEvent({
      action:  'coverage_review.requested',
      orgId,
      userId,
      details: { source: 'user' },
    })

    res.json({ ok: true, data: result.data })
  } catch (err) {
    next(err)
  }
})

export default router
