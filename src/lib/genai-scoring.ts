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

// ── Field value → score ─────────────────────────────────────────────────────
// enterprise-only = 70: available but requires the right license/contract.
// That is a dependency, not a failure.
// na is excluded from scoring entirely — see scoreItems() below.

const POS: Record<string, number> = {
  'yes':             100,
  'configurable':     80,
  'enterprise-only':  70,   // was 0 — available in enterprise tier is acceptable
  'tier-dependent':   60,
  'partial':          60,
  'no-published':     40,   // no public evidence found — not the same as "no"
  'no':                0,
}

const NEG: Record<string, number> = {
  'no':              100,
  'configurable':     80,   // risk exists but is controllable
  'enterprise-only':  70,   // risk exists but scoped to enterprise tier
  'tier-dependent':   60,
  'partial':          60,
  'no-published':     40,
  'yes':               0,
}

const DLP_SCORE: Record<string, number> = {
  'enforcement':   100,
  'monitoring':     80,
  'partial':        60,
  'no-published':   40,
  'not-supported':   0,
}

// ── NA-aware weighted scoring ────────────────────────────────────────────────
// na fields are excluded from the denominator so they don't unfairly penalise
// apps where a standard doesn't apply (e.g. HIPAA BAA for a design tool).

type Dir  = 'pos' | 'neg'
type Item = { val: FieldValue; w: number; dir: Dir }

function scoreItems(items: Item[]): number {
  const applicable = items.filter(i => i.val !== 'na')
  const totalW = applicable.reduce((s, i) => s + i.w, 0)
  if (totalW === 0) return 50 // all fields NA — neutral
  const sum = applicable.reduce((s, { val, w, dir }) => {
    const score = dir === 'pos' ? (POS[val] ?? 40) : (NEG[val] ?? 40)
    return s + score * w
  }, 0)
  return sum / totalW // normalise to 0-100 based on applicable weight
}

function scoreDLPItems(items: Array<{ val: DLPValue; w: number }>): number {
  const totalW = items.reduce((s, i) => s + i.w, 0)
  if (totalW === 0) return 0
  return items.reduce((s, { val, w }) => s + (DLP_SCORE[val] ?? 0) * w, 0) / totalW
}

// ── Sub-score A: Data Governance & Privacy (30% of final) ───────────────────
// trains_on_customer_data intentionally appears here AND in GenAI Risk (D).
// It creates both a privacy exposure AND a model-learning risk — two distinct
// harms that are scored in their respective categories.
function scoreDataGovernance(f: AppFields): number {
  return scoreItems([
    { val: f.trains_on_customer_data,    w: 0.20, dir: 'neg' },
    { val: f.opt_out_of_training,        w: 0.15, dir: 'pos' },
    { val: f.dpa_available,              w: 0.10, dir: 'pos' },
    { val: f.customer_owns_data,         w: 0.10, dir: 'pos' },
    { val: f.data_retention,             w: 0.10, dir: 'pos' },
    { val: f.data_deletion,              w: 0.10, dir: 'pos' },
    { val: f.data_residency,             w: 0.10, dir: 'pos' },
    { val: f.subprocessor_list,          w: 0.05, dir: 'pos' },
    { val: f.pii_sharing_third_parties,  w: 0.05, dir: 'neg' },
    { val: f.data_sharing_genai_vendor,  w: 0.05, dir: 'neg' },
  ])
}

// ── Sub-score B: DLP Activity Support (30% of final) ────────────────────────
// login_instance = tenant / instance identification (label updated in display)
function scoreDLPActivity(dlp: DLPActivities): number {
  return scoreDLPItems([
    { val: dlp.post_prompt,    w: 0.30 },
    { val: dlp.upload,         w: 0.30 },
    { val: dlp.login_instance, w: 0.15 }, // tenant / instance identification
    { val: dlp.edit,           w: 0.10 },
    { val: dlp.response,       w: 0.05 },
    { val: dlp.download,       w: 0.05 },
    { val: dlp.attach,         w: 0.05 },
  ])
}

// ── Sub-score C: Security & Compliance (20% of final) ───────────────────────
function scoreSecurityCompliance(f: AppFields): number {
  return scoreItems([
    { val: f.soc2,                  w: 0.15, dir: 'pos' },
    { val: f.iso27001,              w: 0.15, dir: 'pos' },
    { val: f.iso27018,              w: 0.10, dir: 'pos' },
    { val: f.fedramp,               w: 0.10, dir: 'pos' },
    { val: f.pci_dss,               w: 0.10, dir: 'pos' },
    { val: f.hipaa_baa,             w: 0.10, dir: 'pos' },
    { val: f.encryption_at_rest,    w: 0.10, dir: 'pos' },
    { val: f.encryption_in_transit, w: 0.10, dir: 'pos' },
    { val: f.tenant_segregation,    w: 0.10, dir: 'pos' },
  ])
}

// ── Sub-score D: GenAI-Specific Risk (15% of final) ─────────────────────────
// trains_on_customer_data also appears in A — see comment there.
function scoreGenAIRisk(f: AppFields): number {
  return scoreItems([
    { val: f.trains_on_customer_data,   w: 0.25, dir: 'neg' },
    { val: f.opt_out_of_training,       w: 0.25, dir: 'pos' },
    { val: f.prompt_retention_controls, w: 0.25, dir: 'pos' },
    { val: f.model_provider_clear,      w: 0.15, dir: 'pos' },
    { val: f.connectors_agents_risk,    w: 0.10, dir: 'neg' },
  ])
}

// ── Sub-score E: Breach History & Transparency (5% of final) ────────────────
function scoreBreachTransparency(b: BreachInfo): number {
  return scoreItems([
    { val: b.recent_breach,    w: 0.40, dir: 'neg' },
    { val: b.older_breach,     w: 0.25, dir: 'neg' },
    { val: b.breach_disclosed, w: 0.15, dir: 'pos' },
    { val: b.source_disclosure,w: 0.10, dir: 'pos' },
    { val: b.breach_remediated,w: 0.10, dir: 'pos' },
  ])
}

// ── Hard caps ────────────────────────────────────────────────────────────────
function applyHardCaps(
  score: number,
  f: AppFields,
  dlp: DLPActivities,
  b: BreachInfo,
): { score: number; cap: string | null } {
  let cap: string | null = null
  let max = 100

  // Training on customer data with no opt-out — clear privacy risk
  if (f.trains_on_customer_data === 'yes' && f.opt_out_of_training === 'no') {
    if (max > 60) { max = 60; cap = 'Trains on customer data — no opt-out available' }
  }

  // Training disclosure unclear — vendor has not confirmed either way
  if (f.trains_on_customer_data === 'no-published' && f.opt_out_of_training === 'no-published') {
    if (max > 70) { max = 70; cap = 'Training and opt-out status not publicly disclosed' }
  }

  // DLP blind spot — prompt and upload both uninspectable
  if (dlp.post_prompt === 'not-supported' && dlp.upload === 'not-supported') {
    if (max > 65) { max = 65; cap = 'Prompt and upload inspection both not supported' }
  }

  // Recent breach — unconfirmed remediation is more severe
  if (b.recent_breach === 'yes') {
    if (b.breach_remediated === 'no' || b.breach_remediated === 'no-published') {
      if (max > 70) { max = 70; cap = 'Recent breach — remediation not confirmed' }
    } else {
      if (max > 75) { max = 75; cap = 'Recent breach involving customer data' }
    }
  }

  // No DPA + unclear data ownership — foundational privacy gap
  if (f.dpa_available === 'no' && (f.customer_owns_data === 'no' || f.customer_owns_data === 'no-published')) {
    if (max > 70) { max = 70; cap = 'No DPA and data ownership unclear' }
  }

  // Cannot identify tenant / instance — DLP cannot separate personal vs corporate
  if (dlp.login_instance === 'not-supported') {
    if (max > 80) { max = 80; cap = 'Tenant / instance identification not supported by DLP' }
  }

  // Insufficient public information overall
  const allFields = Object.values(f)
  const noPublishedCount = allFields.filter(v => v === 'no-published').length
  if (noPublishedCount > allFields.length * 0.6) {
    if (max > 55) { max = 55; cap = 'Insufficient public information — verify with vendor' }
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
  const dg = scoreDataGovernance(fields)
  const da = scoreDLPActivity(dlp)
  const sc = scoreSecurityCompliance(fields)
  const gr = scoreGenAIRisk(fields)
  const bt = scoreBreachTransparency(breach)

  const raw = Math.round(dg * 0.30 + da * 0.30 + sc * 0.20 + gr * 0.15 + bt * 0.05)
  const { score: capped, cap } = applyHardCaps(raw, fields, dlp, breach)
  const final = Math.min(capped, 95) // never 100

  const supported = Object.values(dlp).filter(
    v => v === 'enforcement' || v === 'monitoring' || v === 'partial',
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

// ── AI response parsers ───────────────────────────────────────────────────────
// Clamp helpers ensure AI output that drifts outside enum values doesn't crash
// the scoring pipeline — unknown values fall back to 'no-published'.

const VALID_FIELD_VALUES: readonly string[] = [
  'yes', 'no', 'partial', 'enterprise-only', 'tier-dependent',
  'configurable', 'no-published', 'na',
]
const VALID_DLP_VALUES: readonly string[] = [
  'enforcement', 'monitoring', 'partial', 'no-published', 'not-supported',
]

function clampField(v: unknown): FieldValue {
  return VALID_FIELD_VALUES.includes(v as string) ? (v as FieldValue) : 'no-published'
}
function clampDLP(v: unknown): DLPValue {
  return VALID_DLP_VALUES.includes(v as string) ? (v as DLPValue) : 'no-published'
}

export function parseFields(raw: Record<string, unknown>): AppFields {
  return {
    dpa_available:              clampField(raw.dpa_available),
    customer_owns_data:         clampField(raw.customer_owns_data),
    trains_on_customer_data:    clampField(raw.trains_on_customer_data),
    opt_out_of_training:        clampField(raw.opt_out_of_training),
    data_retention:             clampField(raw.data_retention),
    data_deletion:              clampField(raw.data_deletion),
    data_residency:             clampField(raw.data_residency),
    subprocessor_list:          clampField(raw.subprocessor_list),
    pii_sharing_third_parties:  clampField(raw.pii_sharing_third_parties),
    data_sharing_genai_vendor:  clampField(raw.data_sharing_genai_vendor),
    soc2:                       clampField(raw.soc2),
    iso27001:                   clampField(raw.iso27001),
    iso27018:                   clampField(raw.iso27018),
    fedramp:                    clampField(raw.fedramp),
    pci_dss:                    clampField(raw.pci_dss),
    hipaa_baa:                  clampField(raw.hipaa_baa),
    encryption_at_rest:         clampField(raw.encryption_at_rest),
    encryption_in_transit:      clampField(raw.encryption_in_transit),
    tenant_segregation:         clampField(raw.tenant_segregation),
    model_provider_clear:       clampField(raw.model_provider_clear),
    prompt_retention_controls:  clampField(raw.prompt_retention_controls),
    connectors_agents_risk:     clampField(raw.connectors_agents_risk),
  }
}

export function parseDLP(raw: Record<string, unknown>): DLPActivities {
  return {
    post_prompt:    clampDLP(raw.post_prompt),
    upload:         clampDLP(raw.upload),
    login_instance: clampDLP(raw.login_instance),
    edit:           clampDLP(raw.edit),
    response:       clampDLP(raw.response),
    download:       clampDLP(raw.download),
    attach:         clampDLP(raw.attach),
  }
}

export function parseBreach(raw: Record<string, unknown>): BreachInfo {
  return {
    recent_breach:      clampField(raw.recent_breach),
    older_breach:       clampField(raw.older_breach),
    breach_disclosed:   clampField(raw.breach_disclosed),
    source_disclosure:  clampField(raw.source_disclosure),
    breach_remediated:  clampField(raw.breach_remediated),
    breach_name:        typeof raw.breach_name === 'string' ? raw.breach_name : null,
    breach_date:        typeof raw.breach_date === 'string' ? raw.breach_date : null,
    breach_description: typeof raw.breach_description === 'string' ? raw.breach_description : null,
  }
}
