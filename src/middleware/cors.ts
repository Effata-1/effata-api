import corsLib from 'cors'
import { config } from '../config'

const allowedOrigins = new Set(
  config.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean),
)

export const cors = corsLib({
  origin(origin, cb) {
    // Allow server-to-server calls (no Origin header) and listed origins
    if (!origin || allowedOrigins.has(origin)) {
      cb(null, true)
    } else {
      cb(new Error(`CORS: origin ${origin} not allowed`))
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-cron-key'],
})
