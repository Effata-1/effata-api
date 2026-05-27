import { createClient } from '@supabase/supabase-js'
import type { Request, Response, NextFunction } from 'express'
import { config } from '../config'

export interface RequestContext {
  userId: string
  orgId:  string
}

declare global {
  namespace Express {
    interface Request {
      context?: RequestContext
    }
  }
}

const authClient = createClient(config.SUPABASE_URL, config.SUPABASE_ANON_KEY, {
  auth: { autoRefreshToken: false, persistSession: false },
})

export async function validateToken(
  req: Request,
  res: Response,
  next: NextFunction,
): Promise<void> {
  const token = req.headers.authorization?.replace('Bearer ', '')
  if (!token) {
    res.status(401).json({ error: 'Unauthorized' })
    return
  }

  const { data: { user }, error } = await authClient.auth.getUser(token)
  if (error || !user) {
    res.status(401).json({ error: 'Invalid token' })
    return
  }

  // base64url → UTF-8 decode (Supabase JWTs use base64url, not standard base64)
  try {
    const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/')
    const claims = JSON.parse(Buffer.from(b64, 'base64').toString('utf-8')) as Record<string, unknown>
    const orgId = claims?.org_id as string | undefined
    if (!orgId) {
      res.status(401).json({ error: 'Missing org context' })
      return
    }
    req.context = { userId: user.id, orgId }
  } catch {
    res.status(401).json({ error: 'Invalid token claims' })
    return
  }

  next()
}

export function validateCronKey(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (req.headers['x-cron-key'] !== config.CRON_API_KEY) {
    res.status(401).json({ error: 'Unauthorized' })
    return
  }
  next()
}
