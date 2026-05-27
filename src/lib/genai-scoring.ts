type FieldValue =
  | 'yes' | 'no' | 'partial'
  | 'enterprise-only' | 'tier-dependent' | 'configurable'
  | 'no-published' | 'na'

type DLPValue =
  | 'enforcement' | 'monitoring' | 'partial' | 'no-published' | 'not-supported'

export interface AppFields {
  dpa_available: FieldValue
  customer_owns_data: FieldValue
  trains_on_customer_data: FieldValue
  opt_out_of_training: FieldValue
  data_retention: FieldValue
  data_deletion: FieldValue
  data_residency: FieldValue
  subprocessor_list: FieldValue
  pii_sharing_third_parties: FieldValue
  data_sharing_genai_vendor: FieldValue
  soc2: FieldValue
  iso27001: FieldValue
  iso27018: FieldValue
  fedramp: FieldValue
  pci_dss: FieldValue
  hipaa_baa: FieldValue
  encryption_at_rest: FieldValue
  encryption_in_transit: FieldValue
  tenant_segregation: FieldValue
  model_provider_clear: FieldValue
  prompt_retention_controls: FieldValue
  connectors_agents_risk: FieldValue
}

export interface DLPActivities {
  post_prompt: DLPValue
  upload: DLPValue
  login_instance: DLPValue
  edit: DLPValue
  response: DLPValue
  download: DLPValue
  attach: DLPValue
}

export interface BreachInfo {
  recent_breach: FieldValue
  older_breach: FieldValue
  breach_disclosed: FieldValue
  source_disclosure: FieldValue
  breach_remediated: FieldValue
  breach_name?: string | null
  breach_date?: string | null
  breach_description?: string | null
}

export interface TrustScores {
  final_score: number
  raw_score: number
  applied_cap: string | null
  suggested_classification: string
  dlp_activities_supported: number
  dlp_activities_total: number
}

const POS: Record<string, number> = {
  'yes': 100, 'configurable': 80,
  'tier-dependent': 60, 'partial': 60,
  'no-published': 40, 'enterprise-only': 0, 'no': 0, 'na': 0,
}

const NEG: Record<string, number> = {
  'no': 100, 'na': 100,
  'configurable': 80, 'tier-dependent': 60, 'partial': 60,
  'no-published': 40, 'yes': 0,
}

const DLP_SCORE: Record<string, number> = {
  'enforcement': 100, 'monitoring': 80, 'partial': 60,
  'no-published': 40, 'not-supported': 0,
}

const p = (v: FieldValue) => POS[v] ?? 40
const n = (v: FieldValue) => NEG[v] ?? 40
const d = (v: DLPValue)   => DLP_SCORE[v] ?? 0

function scoreDataGovernance(f: AppFields): number {
  return (
    p(f.dpa_available)              * 0.10 +
    p(f.customer_owns_data)         * 0.10 +
    n(f.trains_on_customer_data)    * 0.20 +
    p(f.opt_out_of_training)        * 0.15 +
    p(f.data_retention)             * 0.10 +
    p(f.data_deletion)              * 0.10 +
    p(f.data_residency)             * 0.10 +
    p(f.subprocessor_list)          * 0.05 +
    n(f.pii_sharing_third_parties)  * 0.05 +
    n(f.data_sharing_genai_vendor)  * 0.05
  )
}

function scoreDLPActivity(dlp: DLPActivities): number {
  return (
    d(dlp.post_prompt)    * 0.30 +
    d(dlp.upload)         * 0.30 +
    d(dlp.login_instance) * 0.15 +
    d(dlp.edit)           * 0.10 +
    d(dlp.response)       * 0.05 +
    d(dlp.download)       * 0.05 +
    d(dlp.attach)         * 0.05
  )
}

function scoreSecurityCompliance(f: AppFields): number {
  return (
    p(f.soc2)                * 0.15 +
    p(f.iso27001)            * 0.15 +
    p(f.iso27018)            * 0.10 +
    p(f.fedramp)             * 0.10 +
    p(f.pci_dss)             * 0.10 +
    p(f.hipaa_baa)           * 0.10 +
    p(f.encryption_at_rest)  * 0.10 +
    p(f.encryption_in_transit) * 0.10 +
    p(f.tenant_segregation)  * 0.10
  )
}

function scoreGenAIRisk(f: AppFields): number {
  return (
    p(f.model_provider_clear)      * 0.15 +
    n(f.trains_on_customer_data)   * 0.25 +
    p(f.opt_out_of_training)       * 0.25 +
    p(f.prompt_retention_controls) * 0.25 +
    n(f.connectors_agents_risk)    * 0.10
  )
}

function scoreBreachTransparency(b: BreachInfo): number {
  return (
    n(b.recent_breach)     * 0.40 +
    n(b.older_breach)      * 0.25 +
    p(b.breach_disclosed)  * 0.15 +
    p(b.source_disclosure) * 0.10 +
    p(b.breach_remediated) * 0.10
  )
}

function applyHardCaps(
  score: number,
  f: AppFields,
  dlp: DLPActivities,
  b: BreachInfo,
): { score: number; cap: string | null } {
  let cap: string | null = null
  let max = 100

  if (f.trains_on_customer_data === 'yes' && f.opt_out_of_training === 'no') {
    max = Math.min(max, 60); cap = 'Training on customer data with no opt-out'
  }
  if (dlp.post_prompt === 'not-supported' && dlp.upload === 'not-supported') {
    max = Math.min(max, 65); cap = 'Post/Prompt and Upload both not inspectable'
  }
  if (b.recent_breach === 'yes') { max = Math.min(max, 75); cap = 'Recent breach involving customer data' }

  const allFields = Object.values(f)
  const noPublishedCount = allFields.filter(v => v === 'no-published').length
  if (noPublishedCount > allFields.length * 0.6) {
    max = Math.min(max, 55); cap = 'Insufficient public information'
  }

  return { score: Math.min(score, max), cap }
}

function suggestClassification(score: number): string {
  if (score >= 85) return 'enterprise-approved'
  if (score >= 70) return 'approved-with-conditions'
  if (score >= 50) return 'permitted-with-restriction'
  if (score >= 30) return 'unknown'
  return 'prohibited'
}

const CLASSIFICATION_LABELS: Record<string, string> = {
  'enterprise-approved':        'Approved & Supported GenAI',
  'approved-with-conditions':   'Approved with Conditions',
  'permitted-with-restriction': 'Restricted / Unassessed GenAI',
  'personal':                   'Personal',
  'unknown':                    'Unknown',
  'prohibited':                 'Prohibited GenAI',
}

export function computeTrustScore(
  fields: AppFields,
  dlp: DLPActivities,
  breach: BreachInfo,
): TrustScores {
  const dg  = scoreDataGovernance(fields)
  const da  = scoreDLPActivity(dlp)
  const sc  = scoreSecurityCompliance(fields)
  const gr  = scoreGenAIRisk(fields)
  const bt  = scoreBreachTransparency(breach)

  const raw = Math.round(dg * 0.30 + da * 0.30 + sc * 0.20 + gr * 0.15 + bt * 0.05)
  const { score: capped, cap } = applyHardCaps(raw, fields, dlp, breach)
  const final = Math.min(capped, 95)

  const supported = Object.values(dlp).filter(
    v => v === 'enforcement' || v === 'monitoring' || v === 'partial'
  ).length

  return {
    final_score:              final,
    raw_score:                raw,
    applied_cap:              cap,
    suggested_classification: suggestClassification(final),
    dlp_activities_supported: supported,
    dlp_activities_total:     7,
  }
}

export function classificationLabel(key: string): string {
  return CLASSIFICATION_LABELS[key] ?? '—'
}
