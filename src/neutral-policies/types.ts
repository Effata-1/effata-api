// NeutralPolicyV1 — translation-grade neutral policy schema.
// This is the source of truth for vendor adapters. Vendor-native output is a compiled artifact.

export type NeutralPolicyIntent =
  | 'prevent_exfiltration'   // block
  | 'detect_only'            // monitor / alert
  | 'coach_user'             // coach (any variant)
  | 'allow_approved_use'     // allow for approved scope
  | 'govern_app_access'      // app-level access control — no content detection

export type NeutralActivity =
  | 'browse' | 'upload' | 'download' | 'share' | 'post'
  | 'copy_paste' | 'print' | 'move' | 'delete' | 'email_send' | 'prompt_submit'

export type NeutralChannel =
  | 'web' | 'saas_api' | 'email' | 'endpoint' | 'copilot' | 'chat' | 'files' | 'browser'

// ── Content conditions ─────────────────────────────────────────────────────

export interface DataTypeCondition {
  type:              'data_type'
  effata_data_type:  string    // system_level (e.g. "secret") or catalog slug (e.g. "secret:api-key")
  name:              string
  sensitivity:       string    // system_level value
  confidence:        'low' | 'medium' | 'high'
}

export interface ClassificationLabelCondition {
  type:              'classification_label'
  label_id:          string    // org_customer_sensitivity_labels.id
  label_name:        string
  label_source:      'mip' | 'titus' | 'boldon-james' | 'custom'  // matches DB CHECK constraint
  metadata_key:      string    // e.g. "MSIP_Label_xxx_Enabled"
  metadata_operator: 'equals' | 'contains' | 'exists'
  metadata_value:    string    // e.g. "True"
  sensitivity:       string
}

export interface FilenameCondition {
  type:        'filename'
  name:        string
  pattern:     string          // keyword / glob, e.g. "*secret* OR *password* OR *token*"
  sensitivity: string
}

export type NeutralContentCondition =
  | DataTypeCondition
  | ClassificationLabelCondition
  | FilenameCondition

// ── Scope ──────────────────────────────────────────────────────────────────

export interface NeutralAppCategory {
  id:         string          // org_genai_governance_categories.id
  system_tag: string | null   // e.g. 'permitted-with-restriction' | 'prohibited' | null (custom)
  name:       string          // display name — for readability only, not for adapter logic
}

export interface NeutralScope {
  users:          string[]
  groups:         string[]
  devices:        string[]
  device_posture: string[]
  apps:           string[]
  app_categories: NeutralAppCategory[]  // structured — adapters use system_tag, not name
  app_instances:  string[]
  channels:       NeutralChannel[]      // always explicitly set per policy family
  activities:     NeutralActivity[]     // always explicit — never empty
}

// ── Decision ───────────────────────────────────────────────────────────────

export interface NeutralDecision {
  mode:                    'block' | 'allow' | 'monitor' | 'alert' | 'coach'
  severity:                'info' | 'warning' | 'minor' | 'major' | 'critical'
  require_acknowledgement: boolean
  require_justification:   boolean
  notification_template:   string | null
  preserve_evidence:       boolean
  create_incident:         boolean
}

// ── Exceptions ─────────────────────────────────────────────────────────────

export interface NeutralException {
  effect:         'allow' | 'exclude'
  reason:         string
  scope_override: {
    groups?:        string[]
    apps?:          string[]
    app_instances?: string[]
  }
}

// ── Root type ──────────────────────────────────────────────────────────────

export interface NeutralPolicyV1 {
  schema_version: '1.0'
  id:             string
  name:           string
  description:    string
  intent:         NeutralPolicyIntent
  policy_family:  string
  // Stable compiler-assigned key used for DB upsert. e.g. "genai-content-detection-secret-approved-with-conditions"
  // AI pack policies use "policy-pack-{policy_id}".
  policy_key:     string
  scope:          NeutralScope
  content: {
    operator:   'any' | 'all'
    conditions: NeutralContentCondition[]   // empty only for govern_app_access intent
  }
  decision:   NeutralDecision
  exceptions: NeutralException[]
  telemetry: {
    incident_recipients: string[]
    export_evidence:     boolean
    audit_tags:          string[]
  }
  provenance: {
    generated_from:   'governance-matrix' | 'policy-pack-agent' | 'legacy-backfill' | 'manual'
    source_cells:     string[]   // control matrix cell keys, e.g. "pp|secret|enterprise-approved"
    compiler_version: string
    generated_at:     string     // ISO timestamp
    warnings:         string[]
  }
}

// ── Action → Decision mapping ──────────────────────────────────────────────

export function actionToDecision(
  actionCode: string,
  sensitivity: string,
): NeutralDecision {
  const isHighSeverity = sensitivity === 'secret' || sensitivity === 'highly_confidential'
  switch (actionCode) {
    case 'block':
      return {
        mode: 'block',
        severity: isHighSeverity ? 'critical' : 'major',
        require_acknowledgement: false,
        require_justification:   false,
        notification_template:   null,
        preserve_evidence:       true,
        create_incident:         true,
      }
    case 'alert':
      return {
        mode: 'alert',
        severity: 'major',
        require_acknowledgement: false,
        require_justification:   false,
        notification_template:   null,
        preserve_evidence:       true,
        create_incident:         true,
      }
    case 'coach':
      return {
        mode: 'coach',
        severity: 'major',
        require_acknowledgement: false,
        require_justification:   false,
        notification_template:   null,
        preserve_evidence:       false,
        create_incident:         true,
      }
    case 'coach-ack':
      return {
        mode: 'coach',
        severity: 'major',
        require_acknowledgement: true,
        require_justification:   false,
        notification_template:   null,
        preserve_evidence:       false,
        create_incident:         true,
      }
    case 'coach-just':
      return {
        mode: 'coach',
        severity: 'major',
        require_acknowledgement: true,
        require_justification:   true,
        notification_template:   null,
        preserve_evidence:       false,
        create_incident:         true,
      }
    case 'monitor':
      return {
        mode: 'monitor',
        severity: 'minor',
        require_acknowledgement: false,
        require_justification:   false,
        notification_template:   null,
        preserve_evidence:       false,
        create_incident:         false,
      }
    case 'allow':
    default:
      return {
        mode: 'allow',
        severity: 'info',
        require_acknowledgement: false,
        require_justification:   false,
        notification_template:   null,
        preserve_evidence:       false,
        create_incident:         false,
      }
  }
}

export function actionToIntent(actionCode: string): NeutralPolicyIntent {
  switch (actionCode) {
    case 'block':                   return 'prevent_exfiltration'
    case 'coach':
    case 'coach-ack':
    case 'coach-just':              return 'coach_user'
    case 'monitor':
    case 'alert':                   return 'detect_only'
    case 'allow':                   return 'allow_approved_use'
    default:                        return 'detect_only'
  }
}

// Filename patterns by sensitivity level
export const FILENAME_PATTERNS: Record<string, string> = {
  secret:            '*secret* OR *password* OR *token* OR *api-key* OR *credentials* OR *private-key*',
  highly_confidential: '*confidential* OR *restricted* OR *internal-only* OR *do-not-share*',
}

// Default channels per policy family type
export const CHANNELS_CONTENT_DETECTION: NeutralChannel[]  = ['web', 'browser', 'copilot', 'chat', 'saas_api']
export const CHANNELS_LABEL_DETECTION: NeutralChannel[]    = ['web', 'browser', 'saas_api']
export const CHANNELS_FILENAME_DETECTION: NeutralChannel[] = ['web', 'browser', 'saas_api']
export const CHANNELS_APP_ACCESS: NeutralChannel[]         = ['web', 'browser', 'copilot', 'chat']
export const CHANNELS_APPROVED_USE: NeutralChannel[]       = ['web', 'browser', 'copilot', 'saas_api']
