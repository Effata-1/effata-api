import crypto from 'crypto'
import { serviceClient } from '../lib/supabase'
import { logAuditEvent } from '../lib/audit-log'
import { JOB_CONFIG, isJobType, type ProcessorContext } from './job-config'
import { genaiRefreshProcessor } from './processors/genai-refresh.processor'
import { coverageReviewProcessor } from './processors/coverage-review.processor'
import { evidenceReportProcessor } from './processors/evidence-report.processor'
import { policyPackProcessor } from './processors/policy-pack.processor'

const WORKER_ID = `worker-${crypto.randomUUID().slice(0, 8)}`

type Processor = (ctx: ProcessorContext) => Promise<Record<string, unknown>>

const PROCESSORS: Record<string, Processor> = {
  'genai-refresh':   genaiRefreshProcessor,
  'coverage-review': coverageReviewProcessor,
  'evidence-report': evidenceReportProcessor,
  'policy-pack':     policyPackProcessor,
}

interface ClaimedJob {
  id:              string
  org_id:          string
  user_id:         string | null
  job_type:        string
  payload:         Record<string, unknown>
  attempts:        number
  max_attempts:    number
  total_items:     number | null
  processed_items: number
}

async function setProgress(jobId: string, total: number, processed: number): Promise<void> {
  await serviceClient
    .from('ai_jobs')
    .update({ total_items: total, processed_items: processed })
    .eq('id', jobId)
}

async function markCompleted(job: ClaimedJob, result: Record<string, unknown>, durationMs: number): Promise<void> {
  await serviceClient.from('ai_jobs').update({
    status:       'completed',
    result,
    completed_at: new Date().toISOString(),
  }).eq('id', job.id)

  void logAuditEvent({
    action:     'job.completed',
    orgId:      job.org_id,
    userId:     job.user_id,
    entityType: 'ai_job',
    entityId:   job.id,
    details:    { job_type: job.job_type, duration_ms: durationMs },
  })
}

async function markFailed(job: ClaimedJob, errMsg: string): Promise<void> {
  const isFinal = job.attempts >= job.max_attempts

  if (isFinal) {
    await serviceClient.from('ai_jobs').update({
      status:       'failed',
      error:        errMsg,
      completed_at: new Date().toISOString(),
    }).eq('id', job.id)

    void logAuditEvent({
      action:     'job.failed',
      orgId:      job.org_id,
      userId:     job.user_id,
      entityType: 'ai_job',
      entityId:   job.id,
      details:    { job_type: job.job_type, error: errMsg, attempts: job.attempts },
    })
  } else {
    // Reset to pending so the next poll can retry
    await serviceClient.from('ai_jobs').update({
      status:    'pending',
      locked_at: null,
      locked_by: null,
      error:     errMsg,
    }).eq('id', job.id)
  }
}

export async function runJobLoop(): Promise<void> {
  const { data: rows, error } = await serviceClient.rpc('claim_next_job', { worker_id: WORKER_ID })

  if (error) {
    console.error('[worker] claim error:', error.message)
    return
  }

  const job = (rows as ClaimedJob[] | null)?.[0]
  if (!job) return

  console.log(`[worker] claimed job ${job.id} type=${job.job_type} attempt=${job.attempts}/${job.max_attempts}`)

  if (!isJobType(job.job_type)) {
    await markFailed(job, `Unknown job type: ${job.job_type}`)
    return
  }

  const cfg       = JOB_CONFIG[job.job_type]
  const processor = PROCESSORS[job.job_type]
  const startedAt = Date.now()

  void logAuditEvent({
    action:     'job.started',
    orgId:      job.org_id,
    userId:     job.user_id,
    entityType: 'ai_job',
    entityId:   job.id,
    details:    { job_type: job.job_type, attempt: job.attempts },
  })

  const ctx: ProcessorContext = {
    jobId:   job.id,
    orgId:   job.org_id,
    userId:  job.user_id,
    payload: job.payload,
    setProgress: (total, processed) => setProgress(job.id, total, processed),
  }

  const timeoutPromise = new Promise<never>((_, reject) =>
    setTimeout(
      () => reject(new Error(`Job timed out after ${cfg.timeoutMs}ms`)),
      cfg.timeoutMs,
    )
  )

  try {
    const result = await Promise.race([processor(ctx), timeoutPromise])
    await markCompleted(job, result, Date.now() - startedAt)
    console.log(`[worker] completed job ${job.id} in ${Date.now() - startedAt}ms`)
  } catch (err) {
    const errMsg = err instanceof Error ? err.message : String(err)
    console.error(`[worker] job ${job.id} failed (attempt ${job.attempts}/${job.max_attempts}):`, errMsg)
    await markFailed(job, errMsg)
  }
}
