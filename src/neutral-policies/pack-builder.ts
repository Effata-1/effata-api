import { randomUUID } from 'crypto'
import type { NeutralPolicyV1, NeutralActivity, NeutralChannel, DataTypeCondition } from './types'
import {
  actionToDecision, actionToIntent,
  CHANNELS_CONTENT_DETECTION, CHANNELS_LABEL_DETECTION, CHANNELS_FILENAME_DETECTION,
  CHANNELS_APP_ACCESS, CHANNELS_APPROVED_USE,
} from './types'
import { computeNeutralPolicyHash } from './hash'
import { COMPILER_VERSION } from './compiler'

// ── Input: the AI policy-pack recommendation (from policy-pack.processor) ──────

export interface PackAiPolicy {
  id:                        string   // org_genai_policies.id
  name:                      string
  description:               string
  policy_type:               'usage' | 'data-handling' | 'approved-use' | 'prohibited'
  policy_family:             string
  primary_action:            string
  data_classification_label: string   // 'public'|'internal'|'confidential'|'highly-confidential'|'secret'|'all'
  scope_all_apps:            boolean
  scope_app_ids:             string[]
}

export interface PackBuilderContext {
  inScopeDataTypes: Array<{ slug: string; name: string; system_level: string }>
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// AI pack uses hyphenated label names; internal system_level uses underscores
function labelToSystemLevel(label: string): string {
  if (label === 'highly-confidential') return 'highly_confidential'
  return label
}

function inferActivitiesAndChannels(policyFamily: string): {
  activities: NeutralActivity[]
  channels:   NeutralChannel[]
  clearConditions: boolean
} {
  const family = policyFamily.toLowerCase()
  if (family.includes('label detection') || family.includes('label-detection')) {
    return { activities: ['upload'], channels: CHANNELS_LABEL_DETECTION, clearConditions: false }
  }
  if (family.includes('filename')) {
    return { activities: ['upload'], channels: CHANNELS_FILENAME_DETECTION, clearConditions: false }
  }
  if (family.includes('app access') || family.includes('app-access')) {
    return {
      activities:    ['browse', 'post', 'upload', 'download'],
      channels:      CHANNELS_APP_ACCESS,
      clearConditions: true,
    }
  }
  // Default: content detection (prompt + upload)
  return { activities: ['post', 'upload'], channels: CHANNELS_CONTENT_DETECTION, clearConditions: false }
}

function policyTypeToIntent(
  policyType: PackAiPolicy['policy_type'],
  actionCode: string,
): NeutralPolicyV1['intent'] {
  if (policyType === 'prohibited') return 'prevent_exfiltration'
  if (policyType === 'approved-use') return 'allow_approved_use'
  return actionToIntent(actionCode)
}

// ── Main builder ──────────────────────────────────────────────────────────────

export function buildNeutralPolicyFromPackOutput(
  aiPolicy: PackAiPolicy,
  context: PackBuilderContext,
): { neutralPolicy: NeutralPolicyV1; hash: string } {
  const systemLevel = labelToSystemLevel(aiPolicy.data_classification_label)
  const { activities, channels, clearConditions } = inferActivitiesAndChannels(aiPolicy.policy_family)

  // Build content conditions from in-scope data types at this sensitivity level
  let conditions: DataTypeCondition[] = []
  if (!clearConditions && systemLevel !== 'all') {
    conditions = context.inScopeDataTypes
      .filter(dt => dt.system_level === systemLevel)
      .map(dt => ({
        type:             'data_type' as const,
        effata_data_type: `${systemLevel}:${dt.slug}`,
        name:             dt.name,
        sensitivity:      systemLevel,
        confidence:       'high' as const,
      }))
  } else if (!clearConditions && systemLevel === 'all') {
    // 'all' means multi-level — include any in-scope type above internal
    const relevantLevels = ['secret', 'highly_confidential', 'confidential']
    conditions = context.inScopeDataTypes
      .filter(dt => relevantLevels.includes(dt.system_level))
      .map(dt => ({
        type:             'data_type' as const,
        effata_data_type: `${dt.system_level}:${dt.slug}`,
        name:             dt.name,
        sensitivity:      dt.system_level,
        confidence:       'high' as const,
      }))
  }

  const decision = actionToDecision(aiPolicy.primary_action, systemLevel)
  const intent   = policyTypeToIntent(aiPolicy.policy_type, aiPolicy.primary_action)

  const warnings: string[] = [
    'Activities and channels inferred from policy_family — verify before translating.',
  ]
  if (conditions.length === 0 && !clearConditions) {
    warnings.push(`No in-scope data types found for sensitivity "${aiPolicy.data_classification_label}". Add data types in Data Catalog.`)
  }

  const neutralPolicy: NeutralPolicyV1 = {
    schema_version: '1.0',
    id:             randomUUID(),
    name:           aiPolicy.name,
    description:    aiPolicy.description,
    intent,
    policy_family:  aiPolicy.policy_family,
    policy_key:     `policy-pack-${aiPolicy.id}`,
    scope: {
      users:          [],
      groups:         [],
      devices:        [],
      device_posture: [],
      apps:           aiPolicy.scope_all_apps ? [] : aiPolicy.scope_app_ids,
      app_categories: [],
      app_instances:  [],
      channels,
      activities,
    },
    content: {
      operator:   'any',
      conditions,
    },
    decision,
    exceptions: [],
    telemetry: {
      incident_recipients: [],
      export_evidence:     decision.preserve_evidence,
      audit_tags:          [aiPolicy.policy_family.toLowerCase().replace(/\s+/g, '-')],
    },
    provenance: {
      generated_from:   'policy-pack-agent',
      source_cells:     [],
      compiler_version: COMPILER_VERSION,
      generated_at:     new Date().toISOString(),
      warnings,
    },
  }

  return { neutralPolicy, hash: computeNeutralPolicyHash(neutralPolicy) }
}
