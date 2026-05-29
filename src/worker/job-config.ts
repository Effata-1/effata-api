export type JobType = 'genai-refresh' | 'coverage-review' | 'evidence-report' | 'policy-pack' | 'policy-translate' | 'policy-compile'

export interface JobConfig {
  timeoutMs: number
  minRole:   'admin' | 'analyst'
}

export const JOB_CONFIG: Record<JobType, JobConfig> = {
  'genai-refresh':    { timeoutMs: 10 * 60_000, minRole: 'admin'   },
  'coverage-review':  { timeoutMs:  3 * 60_000, minRole: 'analyst' },
  'evidence-report':  { timeoutMs:  5 * 60_000, minRole: 'analyst' },
  'policy-pack':      { timeoutMs: 15 * 60_000, minRole: 'admin'   },
  'policy-translate': { timeoutMs: 10 * 60_000, minRole: 'analyst' },
  'policy-compile':   { timeoutMs:  5 * 60_000, minRole: 'analyst' },
}

const JOB_TYPES = Object.keys(JOB_CONFIG) as JobType[]

export function isJobType(v: unknown): v is JobType {
  return JOB_TYPES.includes(v as JobType)
}

export interface ProcessorContext {
  jobId:       string
  orgId:       string
  userId:      string | null
  payload:     Record<string, unknown>
  setProgress: (total: number, processed: number) => Promise<void>
}
