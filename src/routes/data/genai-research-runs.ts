import { Router } from 'express'
import { requireRole } from '../../middleware/rbac'
import { serviceClient } from '../../lib/supabase'

const router = Router()

router.get('/', requireRole('analyst'), async (_req, res, next) => {
  try {
    const { data, error } = await serviceClient
      .from('genai_research_runs')
      .select('id, status, started_at, completed_at, apps_checked, apps_updated, apps_added, error, errors, changes')
      .order('started_at', { ascending: false })
      .limit(50)

    if (error) return next(error)
    res.json(data ?? [])
  } catch (err) {
    next(err)
  }
})

export default router
