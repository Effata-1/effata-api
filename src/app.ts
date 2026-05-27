import express from 'express'
import { cors } from './middleware/cors'
import { errorHandler } from './middleware/errors'
import { validateCronKey } from './middleware/auth'
import healthRouter from './routes/health'
import aiRouter from './routes/ai/index'
import internalComplianceRouter from './routes/internal/compliance'

const app = express()

app.set('trust proxy', 1)

app.use(cors)
app.use(express.json({ limit: '1mb' }))

app.use('/health', healthRouter)
app.use('/api/ai', aiRouter)
app.use('/api/internal/compliance-check', validateCronKey, internalComplianceRouter)

app.use(errorHandler)

export default app
