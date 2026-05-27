import type { ProcessorContext } from '../job-config'

export async function evidenceReportProcessor(_ctx: ProcessorContext): Promise<Record<string, unknown>> {
  throw new Error('evidence-report processor not yet implemented')
}
