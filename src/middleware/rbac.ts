import type { Request, Response, NextFunction } from 'express'
import { serviceClient } from '../lib/supabase'

const ROLE_RANK: Record<string, number> = { admin: 2, analyst: 1, read_only: 0 }

export function requireRole(minRole: 'admin' | 'analyst') {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const ctx = req.context
    if (!ctx) {
      res.status(401).json({ error: 'Unauthorized' })
      return
    }

    const { data, error } = await serviceClient
      .from('profiles')
      .select('role')
      .eq('id', ctx.userId)
      .eq('org_id', ctx.orgId)
      .single()

    if (error || !data) {
      res.status(403).json({ error: 'Profile not found' })
      return
    }

    const userRank = ROLE_RANK[data.role as string] ?? -1
    if (userRank < ROLE_RANK[minRole]) {
      res.status(403).json({ error: 'Insufficient permissions' })
      return
    }

    next()
  }
}
