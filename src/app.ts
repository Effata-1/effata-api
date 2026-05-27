import express from 'express'
import { cors } from './middleware/cors'
import { errorHandler } from './middleware/errors'
import { validateToken, validateCronKey } from './middleware/auth'
import healthRouter              from './routes/health'
import aiRouter                  from './routes/ai/index'
import dataRouter                from './routes/data/index'
import jobsRouter                from './routes/jobs/index'
import internalComplianceRouter  from './routes/internal/compliance'
import internalGenaiRefreshRouter from './routes/internal/genai-refresh'

const app = express()

app.set('trust proxy', 1)

app.use(cors)
app.use(express.json({ limit: '1mb' }))

app.use('/health',                              healthRouter)
app.use('/api/ai',                              aiRouter)
app.use('/api/data',                            validateToken, dataRouter)
app.use('/api/jobs',                            validateToken, jobsRouter)
app.use('/api/internal/compliance-check',       validateCronKey, internalComplianceRouter)
app.use('/api/internal/genai-refresh',          validateCronKey, internalGenaiRefreshRouter)

app.use(errorHandler)

export default app
