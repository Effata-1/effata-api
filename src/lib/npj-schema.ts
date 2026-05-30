// Simplified high-level NPJ validation — used by the AI policy creation route.
// This is NOT the strict NeutralPolicyV1Schema used by vendor adapters (see neutral-policies/schema.ts).
// Mirror of effata/src/lib/genai/npj-schema.ts — keep in sync until a shared monorepo package exists.

export const VALID_INTENTS = [
  'prevent_exfiltration',
  'detect_only',
  'coach_user',
  'allow_approved_use',
  'govern_app_access',
  'label_or_classify',
  'govern_data_at_rest',
] as const

export type NpjIntent = typeof VALID_INTENTS[number]

export const VALID_DECISION_MODES = ['allow', 'monitor', 'alert', 'coach', 'block'] as const
export type NpjDecisionMode = typeof VALID_DECISION_MODES[number]

export const VALID_ACTIVITIES = [
  'browse', 'post', 'prompt_submit', 'upload', 'download',
  'response', 'share', 'copy_paste', 'print', 'email_send',
] as const

export const VALID_CONDITION_TYPES = ['data_type', 'classification_label', 'filename'] as const

export const VALID_OPERATORS = ['any', 'all'] as const
export type NpjOperator = typeof VALID_OPERATORS[number]

export interface NpjValidationResult {
  valid:  boolean
  errors: string[]
}

export function validateNeutralPolicy(npj: unknown): NpjValidationResult {
  const errors: string[] = []

  if (!npj || typeof npj !== 'object') {
    return { valid: false, errors: ['NPJ is not an object'] }
  }

  const n = npj as Record<string, unknown>

  if (n.schema_version !== '1.0') errors.push('schema_version must be "1.0"')

  if (!VALID_INTENTS.includes(n.intent as NpjIntent)) {
    errors.push(`Invalid intent: "${n.intent}". Must be one of: ${VALID_INTENTS.join(', ')}`)
  }

  if (!n.decision || typeof n.decision !== 'object') {
    errors.push('Missing decision object')
  } else {
    const dec = n.decision as Record<string, unknown>
    if (!VALID_DECISION_MODES.includes(dec.mode as NpjDecisionMode)) {
      errors.push(`Invalid decision.mode: "${dec.mode}". Must be one of: ${VALID_DECISION_MODES.join(', ')}`)
    }
  }

  const scope = (n.scope ?? {}) as Record<string, unknown>
  const activities = (scope.activities ?? []) as unknown[]
  for (const a of activities) {
    if (!VALID_ACTIVITIES.includes(a as typeof VALID_ACTIVITIES[number])) {
      errors.push(`Invalid activity: "${a}"`)
    }
  }

  // govern_app_access: activities must be exactly browse + login
  if (n.intent === 'govern_app_access') {
    const APP_ACCESS_ONLY = ['browse', 'login']
    const invalid = activities.filter(a => !APP_ACCESS_ONLY.includes(a as string))
    if (invalid.length > 0) {
      errors.push(`govern_app_access activities must be ["browse", "login"] only. Remove: ${invalid.join(', ')}`)
    }
  }

  const content = (n.content ?? {}) as Record<string, unknown>
  if (content.operator !== undefined && !VALID_OPERATORS.includes(content.operator as NpjOperator)) {
    errors.push(`Invalid content.operator: "${content.operator}". Must be 'any' or 'all'`)
  }
  for (const c of (content.conditions ?? []) as Array<Record<string, unknown>>) {
    if (!VALID_CONDITION_TYPES.includes(c.type as typeof VALID_CONDITION_TYPES[number])) {
      errors.push(`Invalid condition type: "${c.type}"`)
    }
  }

  return { valid: errors.length === 0, errors }
}

export interface ProposalValidationResult {
  valid:  boolean
  errors: string[]
}

export function validatePolicyProposal(proposal: unknown): ProposalValidationResult {
  const errors: string[] = []

  if (!proposal || typeof proposal !== 'object') {
    return { valid: false, errors: ['proposal is not an object'] }
  }

  const p = proposal as Record<string, unknown>

  if (!p.name || typeof p.name !== 'string' || !p.name.trim()) {
    errors.push('Missing proposal.name')
  }
  if (typeof p.description !== 'string') {
    errors.push('Missing proposal.description')
  }
  if (!p.npj || typeof p.npj !== 'object') {
    errors.push('Missing proposal.npj')
  }
  if (!Array.isArray(p.sourceImpact)) {
    errors.push('Missing proposal.sourceImpact array')
  }
  if (!Array.isArray(p.translationImpact)) {
    errors.push('Missing proposal.translationImpact array')
  }

  if (errors.length > 0) return { valid: false, errors }

  // Deep NPJ validation
  const npjResult = validateNeutralPolicy(p.npj)
  return { valid: npjResult.valid, errors: npjResult.errors }
}
