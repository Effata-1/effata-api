import type { ProcessorContext } from '../job-config'

export async function policyPackProcessor(_ctx: ProcessorContext): Promise<Record<string, unknown>> {
  throw new Error('policy-pack processor not yet implemented')
}
