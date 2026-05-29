import { z } from 'zod'
import type { NeutralPolicyV1 } from './types'

const NeutralAppCategorySchema = z.object({
  id:         z.string(),
  system_tag: z.string().nullable(),
  name:       z.string(),
})

const DataTypeConditionSchema = z.object({
  type:             z.literal('data_type'),
  effata_data_type: z.string(),
  name:             z.string(),
  sensitivity:      z.string(),
  confidence:       z.enum(['low', 'medium', 'high']),
})

const ClassificationLabelConditionSchema = z.object({
  type:              z.literal('classification_label'),
  label_id:          z.string(),
  label_name:        z.string(),
  label_source:      z.enum(['mip', 'titus', 'boldon-james', 'custom']),
  metadata_key:      z.string(),
  metadata_operator: z.enum(['equals', 'contains', 'exists']),
  metadata_value:    z.string(),
  sensitivity:       z.string(),
})

const FilenameConditionSchema = z.object({
  type:        z.literal('filename'),
  name:        z.string(),
  pattern:     z.string(),
  sensitivity: z.string(),
})

const NeutralContentConditionSchema = z.discriminatedUnion('type', [
  DataTypeConditionSchema,
  ClassificationLabelConditionSchema,
  FilenameConditionSchema,
])

const NeutralDecisionSchema = z.object({
  mode:                    z.enum(['block', 'allow', 'monitor', 'alert', 'coach']),
  severity:                z.enum(['info', 'warning', 'minor', 'major', 'critical']),
  require_acknowledgement: z.boolean(),
  require_justification:   z.boolean(),
  notification_template:   z.string().nullable(),
  preserve_evidence:       z.boolean(),
  create_incident:         z.boolean(),
})

const NeutralExceptionSchema = z.object({
  effect:         z.enum(['allow', 'exclude']),
  reason:         z.string(),
  scope_override: z.object({
    groups:        z.array(z.string()).optional(),
    apps:          z.array(z.string()).optional(),
    app_instances: z.array(z.string()).optional(),
  }),
})

export const NeutralPolicyV1Schema = z.object({
  schema_version: z.literal('1.0'),
  id:             z.string(),
  name:           z.string(),
  description:    z.string(),
  intent:         z.enum(['prevent_exfiltration', 'detect_only', 'coach_user', 'allow_approved_use', 'govern_app_access']),
  policy_family:  z.string(),
  policy_key:     z.string(),
  scope: z.object({
    users:          z.array(z.string()),
    groups:         z.array(z.string()),
    devices:        z.array(z.string()),
    device_posture: z.array(z.string()),
    apps:           z.array(z.string()),
    app_categories: z.array(NeutralAppCategorySchema),
    app_instances:  z.array(z.string()),
    channels:       z.array(z.enum(['web', 'saas_api', 'email', 'endpoint', 'copilot', 'chat', 'files', 'browser'])).min(1),
    activities:     z.array(z.enum(['browse', 'upload', 'download', 'share', 'post', 'copy_paste', 'print', 'move', 'delete', 'email_send', 'prompt_submit'])).min(1),
  }),
  content: z.object({
    operator:   z.enum(['any', 'all']),
    conditions: z.array(NeutralContentConditionSchema),
  }),
  decision:   NeutralDecisionSchema,
  exceptions: z.array(NeutralExceptionSchema),
  telemetry: z.object({
    incident_recipients: z.array(z.string()),
    export_evidence:     z.boolean(),
    audit_tags:          z.array(z.string()),
  }),
  provenance: z.object({
    generated_from:   z.enum(['governance-matrix', 'policy-pack-agent', 'legacy-backfill', 'manual']),
    source_cells:     z.array(z.string()),
    compiler_version: z.string(),
    generated_at:     z.string(),
    warnings:         z.array(z.string()),
  }),
})

export function validateNeutralPolicy(json: unknown): NeutralPolicyV1 | null {
  const result = NeutralPolicyV1Schema.safeParse(json)
  return result.success ? result.data : null
}
