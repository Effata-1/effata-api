import rateLimit from 'express-rate-limit'

export const aiRateLimit = rateLimit({
  windowMs:        60_000,
  max:             20,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: 'Too many requests — slow down' },
  keyGenerator:    (req) => req.context?.userId ?? req.ip ?? 'anonymous',
})
