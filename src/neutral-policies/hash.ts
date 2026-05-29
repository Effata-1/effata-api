import { createHash } from 'crypto'
import type { NeutralPolicyV1 } from './types'

function sortedStringify(obj: unknown): string {
  if (obj === null || typeof obj !== 'object') return JSON.stringify(obj)
  if (Array.isArray(obj)) return '[' + obj.map(sortedStringify).join(',') + ']'
  const keys = Object.keys(obj as Record<string, unknown>).sort()
  const pairs = keys.map(k => JSON.stringify(k) + ':' + sortedStringify((obj as Record<string, unknown>)[k]))
  return '{' + pairs.join(',') + '}'
}

export function computeNeutralPolicyHash(policy: NeutralPolicyV1): string {
  const stable = sortedStringify({ scope: policy.scope, content: policy.content, decision: policy.decision })
  return createHash('sha256').update(stable).digest('hex')
}
