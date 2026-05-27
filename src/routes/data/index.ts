import { Router } from 'express'
import teamRouter        from './team'
import genaiAppsRouter   from './genai-apps'
import researchRunsRouter from './genai-research-runs'
import coverageRouter    from './coverage-review'

const router = Router()

router.use('/team',                teamRouter)
router.use('/genai-apps',          genaiAppsRouter)
router.use('/genai-research-runs', researchRunsRouter)
router.use('/coverage-review',     coverageRouter)

export default router
