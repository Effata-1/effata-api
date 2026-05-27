import { Router } from 'express'
import { validateToken } from '../../middleware/auth'
import { aiRateLimit } from '../../middleware/rate-limit'
import runRouter from './run'
import advisorRouter from './advisor'
import policyChatRouter from './policy-chat'

const router = Router()

router.use(validateToken)
router.use(aiRateLimit)

router.use('/run', runRouter)
router.use('/dlp-advisor', advisorRouter)
router.use('/policy-chat', policyChatRouter)

export default router
