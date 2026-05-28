import type { Request, Response, NextFunction } from 'express'

function extractMessage(err: unknown): string {
  if (err instanceof Error) return err.message
  if (typeof err === 'object' && err !== null) {
    const o = err as Record<string, unknown>
    if (typeof o.message === 'string') return o.message
    return JSON.stringify(o)
  }
  return String(err)
}

export function errorHandler(
  err: unknown,
  _req: Request,
  res: Response,
  _next: NextFunction,
): void {
  const message = extractMessage(err)
  console.error('[error]', message)
  res.status(500).json({ error: message || 'Internal server error' })
}
