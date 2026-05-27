import { runJobLoop } from './job-runner'

const POLL_INTERVAL_MS = 5000

console.log('[worker] started — polling every', POLL_INTERVAL_MS, 'ms')

setInterval(() => {
  runJobLoop().catch(err =>
    console.error('[worker] unhandled loop error:', err instanceof Error ? err.message : err)
  )
}, POLL_INTERVAL_MS)

runJobLoop().catch(err =>
  console.error('[worker] unhandled loop error:', err instanceof Error ? err.message : err)
)
