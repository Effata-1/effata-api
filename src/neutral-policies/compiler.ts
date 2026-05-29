import {
  NeutralPolicyV1, NeutralAppCategory, DataTypeCondition,
  ClassificationLabelCondition, FilenameCondition, NeutralActivity, NeutralChannel,
  actionToDecision, actionToIntent,
  FILENAME_PATTERNS,
  CHANNELS_CONTENT_DETECTION, CHANNELS_LABEL_DETECTION,
  CHANNELS_FILENAME_DETECTION, CHANNELS_APP_ACCESS, CHANNELS_APPROVED_USE,
} from './types'
import { computeNeutralPolicyHash } from './hash'

export const COMPILER_VERSION = '1.0.0'

// ── Input types ───────────────────────────────────────────────────────────────

export interface GovernanceCategoryRow {
  id:         string
  system_tag: string | null
  name:       string
  active:     boolean
}

export interface ControlMatrixOverrideRow {
  data_type:   string
  category_id: string
  action_code: string
}

export interface ClassificationLabelRow {
  id:           string
  system_level: string   // 'secret' | 'highly_confidential' | 'confidential' | 'internal' | 'public'
  name:         string
  active:       boolean
}

export interface CustomerSensitivityLabelRow {
  id:           string
  display_name: string
  label_key:    string
  label_value:  string
  label_source: string
  system_level: string | null
  active:       boolean
}

export interface CatalogDataTypeRow {
  slug:         string
  name:         string
  system_level: string
}

export interface CompilerInput {
  orgId:                    string
  governanceCategories:     GovernanceCategoryRow[]
  controlMatrixOverrides:   ControlMatrixOverrideRow[]
  classificationLabels:     ClassificationLabelRow[]     // org_classification_labels — Effata 5-level
  customerSensitivityLabels: CustomerSensitivityLabelRow[] // org_customer_sensitivity_labels
  inScopeDataTypes:         CatalogDataTypeRow[]          // catalog_data_types filtered to org in-scope only
  onboardingProfile:        { tools: string[]; channels?: string[]; rollout_mode?: string }
}

// ── Output type ───────────────────────────────────────────────────────────────

export interface PolicyRule {
  data_type:   string
  post_prompt: string
  upload:      string
  download:    string
  response:    string
}

export interface CompilerPolicyOutput {
  neutralPolicy: NeutralPolicyV1
  hash:          string
  legacyFields: {
    name:                      string
    description:               string
    policy_type:               string
    policy_family:             string
    primary_action:            string
    data_classification_label: string | null
    scope_all_apps:            boolean
    scope_app_ids:             string[]
    rules:                     PolicyRule[]
    generated_from:            string
    priority:                  number
  }
}

// ── Action priority ───────────────────────────────────────────────────────────

const ACTION_RANK: Record<string, number> = {
  'not-set':    0,
  'allow':      1,
  'monitor':    2,
  'alert':      3,
  'coach':      4,
  'coach-ack':  4,
  'coach-just': 4,
  'block':      5,
}

function mostRestrictive(actions: string[]): string {
  return actions.reduce((best, a) =>
    (ACTION_RANK[a] ?? 0) > (ACTION_RANK[best] ?? 0) ? a : best, 'not-set')
}

const SYSTEM_LEVEL_TO_LABEL: Record<string, string> = {
  secret:              'secret',
  highly_confidential: 'highly-confidential',
  confidential:        'confidential',
  internal:            'internal',
  public:              'public',
}

const SYSTEM_LEVEL_PRIORITY: Record<string, number> = {
  secret: 1, highly_confidential: 2, confidential: 3, internal: 4, public: 5,
}

const CONTENT_DETECTION_ACTIVITIES: NeutralActivity[] = ['post', 'upload']
const LABEL_DETECTION_ACTIVITIES: NeutralActivity[]   = ['upload']
const FILENAME_DETECTION_ACTIVITIES: NeutralActivity[] = ['upload']
const APP_ACCESS_ACTIVITIES: NeutralActivity[]        = ['browse', 'post', 'upload', 'download']
const APPROVED_USE_ACTIVITIES: NeutralActivity[]      = ['browse', 'post', 'upload']

// ── Compiler ──────────────────────────────────────────────────────────────────

export function compileNeutralPoliciesForOrg(input: CompilerInput): CompilerPolicyOutput[] {
  const {
    governanceCategories, controlMatrixOverrides, classificationLabels,
    customerSensitivityLabels, inScopeDataTypes,
  } = input

  const activeCats = governanceCategories.filter(c => c.active)
  const activeLabels = classificationLabels.filter(l => l.active)
  const activeCustomerLabels = customerSensitivityLabels.filter(l => l.active)

  // Override lookup: data_type::category_id → action_code
  const overrideMap = new Map<string, string>()
  for (const o of controlMatrixOverrides) {
    overrideMap.set(`${o.data_type}::${o.category_id}`, o.action_code)
  }

  // Default matrix tables (mirror the frontend control-matrix-client defaults)
  const PP_DEFAULTS: Record<string, Record<string, string>> = {
    'enterprise-approved':        { public: 'allow',   internal: 'monitor', confidential: 'alert',     highly_confidential: 'coach-ack', secret: 'block' },
    'approved-with-conditions':   { public: 'allow',   internal: 'monitor', confidential: 'coach',     highly_confidential: 'block',     secret: 'block' },
    'permitted-with-restriction': { public: 'monitor', internal: 'coach',   confidential: 'block',     highly_confidential: 'block',     secret: 'block' },
    'prohibited':                 { public: 'block',   internal: 'block',   confidential: 'block',     highly_confidential: 'block',     secret: 'block' },
  }
  const UL_DC_DEFAULTS: Record<string, Record<string, string>> = {
    'enterprise-approved':        { public: 'allow',   internal: 'monitor', confidential: 'alert',     highly_confidential: 'coach-ack', secret: 'block' },
    'approved-with-conditions':   { public: 'allow',   internal: 'monitor', confidential: 'coach',     highly_confidential: 'block',     secret: 'block' },
    'permitted-with-restriction': { public: 'monitor', internal: 'coach',   confidential: 'block',     highly_confidential: 'block',     secret: 'block' },
    'prohibited':                 { public: 'block',   internal: 'block',   confidential: 'block',     highly_confidential: 'block',     secret: 'block' },
  }
  const UL_FN_DEFAULTS: Record<string, Record<string, string>> = {
    'enterprise-approved':        { highly_confidential: 'alert',     secret: 'block' },
    'approved-with-conditions':   { highly_confidential: 'coach-ack', secret: 'block' },
    'permitted-with-restriction': { highly_confidential: 'block',     secret: 'block' },
    'prohibited':                 { highly_confidential: 'block',     secret: 'block' },
  }

  function getCellAction(dataType: string, catId: string, catTag: string | null, level: string, defaults: Record<string, Record<string, string>>): string {
    const explicit = overrideMap.get(`${dataType}::${catId}`)
    if (explicit !== undefined) return explicit
    return (catTag && defaults[catTag]?.[level]) ?? 'not-set'
  }

  function toAppCategory(cat: GovernanceCategoryRow): NeutralAppCategory {
    return { id: cat.id, system_tag: cat.system_tag, name: cat.name }
  }

  function buildNeutralPolicy(
    id: string,
    name: string,
    description: string,
    policyKey: string,
    policyFamily: string,
    appCategories: NeutralAppCategory[],
    activities: NeutralActivity[],
    channels: NeutralChannel[],
    conditions: (DataTypeCondition | ClassificationLabelCondition | FilenameCondition)[],
    actionCode: string,
    sensitivity: string,
    sourceCells: string[],
    warnings: string[],
  ): NeutralPolicyV1 {
    const decision  = actionToDecision(actionCode, sensitivity)
    const intent    = appCategories.some(c => c.system_tag === 'prohibited') && conditions.length === 0
      ? 'govern_app_access'
      : actionCode === 'allow' ? 'allow_approved_use' : actionToIntent(actionCode)

    return {
      schema_version: '1.0',
      id,
      name,
      description,
      intent,
      policy_family: policyFamily,
      policy_key: policyKey,
      scope: {
        users: [], groups: [], devices: [], device_posture: [],
        apps: [], app_categories: appCategories, app_instances: [],
        channels, activities,
      },
      content: { operator: 'any', conditions },
      decision,
      exceptions: [],
      telemetry: {
        incident_recipients: [],
        export_evidence: decision.preserve_evidence,
        audit_tags: [policyFamily.toLowerCase().replace(/\s+/g, '-')],
      },
      provenance: {
        generated_from: 'governance-matrix',
        source_cells: sourceCells,
        compiler_version: COMPILER_VERSION,
        generated_at: new Date().toISOString(),
        warnings,
      },
    }
  }

  function wrapOutput(
    npj: NeutralPolicyV1,
    policyType: string,
    dataClassLabel: string | null,
    scopeAllApps: boolean,
    rules: PolicyRule[],
    priority: number,
  ): CompilerPolicyOutput {
    const hash = computeNeutralPolicyHash(npj)
    return {
      neutralPolicy: { ...npj, provenance: { ...npj.provenance } },
      hash,
      legacyFields: {
        name:                      npj.name,
        description:               npj.description,
        policy_type:               policyType,
        policy_family:             npj.policy_family,
        primary_action:            npj.decision.mode === 'coach' ? 'coach' : npj.decision.mode,
        data_classification_label: dataClassLabel,
        scope_all_apps:            scopeAllApps,
        scope_app_ids:             [],
        rules,
        generated_from:            'governance-matrix',
        priority,
      },
    }
  }

  const outputs: CompilerPolicyOutput[] = []
  let priority = 1

  // ── A. App Access Control — Prohibited (always) ──────────────────────────
  const prohibitedCat = activeCats.find(c => c.system_tag === 'prohibited')
  if (prohibitedCat) {
    const policyKey = 'genai-app-access-prohibited'
    const npj = buildNeutralPolicy(
      policyKey,
      'GenAI — Prohibited Apps — Block Access',
      'Block all access to prohibited GenAI apps.',
      policyKey,
      'GenAI App Access Control',
      [toAppCategory(prohibitedCat)],
      APP_ACCESS_ACTIVITIES,
      CHANNELS_APP_ACCESS,
      [],
      'block',
      'secret',
      [`app-access::prohibited::${prohibitedCat.id}`],
      [],
    )
    outputs.push(wrapOutput(npj, 'prohibited', null, false, [], priority++))
  }

  // ── A. App Access Control — Restricted/Unassessed (only if restrictive override) ──
  const restrictedCat = activeCats.find(c => c.system_tag === 'permitted-with-restriction')
  if (restrictedCat) {
    // Only generate if there's at least one restrictive matrix cell for this category
    const hasRestrictiveOverride = controlMatrixOverrides.some(
      o => o.category_id === restrictedCat.id &&
        (ACTION_RANK[o.action_code] ?? 0) >= ACTION_RANK['coach']
    )
    if (hasRestrictiveOverride) {
      const topAction = mostRestrictive(
        controlMatrixOverrides
          .filter(o => o.category_id === restrictedCat.id)
          .map(o => o.action_code)
      )
      const policyKey = 'genai-app-access-restricted'
      const npj = buildNeutralPolicy(
        policyKey,
        'GenAI — Restricted / Unassessed Apps — Access Control',
        'Control access to restricted or unassessed GenAI apps based on configured matrix actions.',
        policyKey,
        'GenAI App Access Control',
        [toAppCategory(restrictedCat)],
        APP_ACCESS_ACTIVITIES,
        CHANNELS_APP_ACCESS,
        [],
        topAction,
        'secret',
        [`app-access::permitted-with-restriction::${restrictedCat.id}`],
        [],
      )
      outputs.push(wrapOutput(npj, 'data-handling', null, false, [], priority++))
    }
  }

  // ── B. Content Detection (pp| rows) ──────────────────────────────────────
  // Group by (system_level, action): combine categories sharing the same action into one policy.
  for (const lbl of [...activeLabels].sort((a, b) =>
    (SYSTEM_LEVEL_PRIORITY[a.system_level] ?? 9) - (SYSTEM_LEVEL_PRIORITY[b.system_level] ?? 9)
  )) {
    const dataType = `pp|${lbl.id}`
    // Map: action → [categories with that action]
    const actionToCats = new Map<string, GovernanceCategoryRow[]>()
    for (const cat of activeCats) {
      const action = getCellAction(dataType, cat.id, cat.system_tag, lbl.system_level, PP_DEFAULTS)
      if (action === 'not-set' || action === 'allow') continue
      const list = actionToCats.get(action) ?? []
      list.push(cat)
      actionToCats.set(action, list)
    }

    for (const [actionCode, cats] of actionToCats) {
      const allCats = activeCats.length > 0 && cats.length === activeCats.length
      const conditions: DataTypeCondition[] = inScopeDataTypes
        .filter(dt => dt.system_level === lbl.system_level)
        .map(dt => ({
          type:             'data_type' as const,
          effata_data_type: `${lbl.system_level}:${dt.slug}`,
          name:             dt.name,
          sensitivity:      lbl.system_level,
          confidence:       'high' as const,
        }))
      const warnings: string[] = conditions.length === 0
        ? [`No in-scope data types found for sensitivity level "${lbl.system_level}". Add data types in Data Catalog.`]
        : []

      const catNames = cats.map(c => c.name).join(', ')
      const levelLabel = SYSTEM_LEVEL_TO_LABEL[lbl.system_level] ?? lbl.system_level
      const policyKey  = `genai-content-${lbl.system_level}-${actionCode}`
      const sourceCells = cats.map(c => `pp|${lbl.system_level}|${c.system_tag ?? c.id}`)

      const npj = buildNeutralPolicy(
        policyKey,
        `GenAI — ${lbl.name} Content — ${actionCode.charAt(0).toUpperCase() + actionCode.slice(1)} — Prompt/Upload`,
        `${actionCode === 'block' ? 'Block' : actionCode === 'coach' ? 'Coach on' : 'Alert on'} ${lbl.system_level} content submitted to GenAI apps${allCats ? '' : ` (${catNames})`}.`,
        policyKey,
        'GenAI Content Detection',
        cats.map(toAppCategory),
        CONTENT_DETECTION_ACTIVITIES,
        CHANNELS_CONTENT_DETECTION,
        conditions,
        actionCode,
        lbl.system_level,
        sourceCells,
        warnings,
      )
      outputs.push(wrapOutput(
        npj, 'data-handling', levelLabel,
        allCats, [], priority++,
      ))
    }
  }

  // ── C. Label Detection (ul|dc| rows) ─────────────────────────────────────
  for (const clbl of activeCustomerLabels) {
    const dataType = `ul|dc|clabel:${clbl.id}`
    // Most restrictive action across all governance categories
    const actionCode = mostRestrictive(
      activeCats.map(cat => {
        const explicit = overrideMap.get(`${dataType}::${cat.id}`)
        if (explicit !== undefined) return explicit
        const sysLevel = clbl.system_level ?? 'confidential'
        return (cat.system_tag && UL_DC_DEFAULTS[cat.system_tag]?.[sysLevel]) ?? 'not-set'
      })
    )
    if (actionCode === 'not-set' || actionCode === 'allow') continue

    const policyKey = `genai-label-detection-${clbl.id}`
    const condition: ClassificationLabelCondition = {
      type:              'classification_label',
      label_id:          clbl.id,
      label_name:        clbl.display_name,
      label_source:      clbl.label_source as ClassificationLabelCondition['label_source'],
      metadata_key:      clbl.label_key,
      metadata_operator: 'equals',
      metadata_value:    clbl.label_value,
      sensitivity:       clbl.system_level ?? 'confidential',
    }

    const npj = buildNeutralPolicy(
      policyKey,
      `GenAI — ${clbl.display_name} Label Detection — Upload Control`,
      `${actionCode === 'block' ? 'Block' : 'Coach on'} uploads of documents labelled "${clbl.display_name}".`,
      policyKey,
      'GenAI Label Detection',
      [],          // applies across all apps — scope is defined by label condition
      LABEL_DETECTION_ACTIVITIES,
      CHANNELS_LABEL_DETECTION,
      [condition],
      actionCode,
      clbl.system_level ?? 'confidential',
      [`ul|dc|clabel:${clbl.id}`],
      [],
    )
    const levelLabel = SYSTEM_LEVEL_TO_LABEL[clbl.system_level ?? 'confidential'] ?? null
    outputs.push(wrapOutput(npj, 'data-handling', levelLabel, true, [], priority++))
  }

  // ── D. Filename Detection (ul|fn| rows) — HC and Secret only ─────────────
  const fnLevels = ['highly_confidential', 'secret'] as const
  for (const level of fnLevels) {
    const matchingLabel = activeLabels.find(l => l.system_level === level)
    if (!matchingLabel) continue

    const dataType = `ul|fn|${matchingLabel.id}`
    const actionCode = mostRestrictive(
      activeCats.map(cat => {
        const explicit = overrideMap.get(`${dataType}::${cat.id}`)
        if (explicit !== undefined) return explicit
        return (cat.system_tag && UL_FN_DEFAULTS[cat.system_tag]?.[level]) ?? 'not-set'
      })
    )
    if (actionCode === 'not-set' || actionCode === 'allow') continue

    const pattern = FILENAME_PATTERNS[level] ?? ''
    const condition: FilenameCondition = {
      type:        'filename',
      name:        `${matchingLabel.name} filename indicators`,
      pattern,
      sensitivity: level,
    }

    const policyKey = `genai-filename-detection-${level}`
    const npj = buildNeutralPolicy(
      policyKey,
      `GenAI — ${matchingLabel.name} — Filename Detection — Upload Control`,
      `${actionCode === 'block' ? 'Block' : 'Coach on'} uploads where filename indicates ${level.replace('_', ' ')} content.`,
      policyKey,
      'GenAI Filename Detection',
      [],
      FILENAME_DETECTION_ACTIVITIES,
      CHANNELS_FILENAME_DETECTION,
      [condition],
      actionCode,
      level,
      [`ul|fn|${level}`],
      [],
    )
    outputs.push(wrapOutput(
      npj, 'data-handling', SYSTEM_LEVEL_TO_LABEL[level] ?? null, true, [], priority++,
    ))
  }

  // ── E. Approved Use — enterprise-approved category ────────────────────────
  const approvedCat = activeCats.find(c => c.system_tag === 'enterprise-approved')
  if (approvedCat) {
    const policyKey = 'genai-approved-use-enterprise'
    const npj = buildNeutralPolicy(
      policyKey,
      'GenAI — Approved & Supported Apps — Allow Approved Usage',
      'Permit approved enterprise GenAI usage after sensitive-data controls are applied.',
      policyKey,
      'GenAI Approved Usage',
      [toAppCategory(approvedCat)],
      APPROVED_USE_ACTIVITIES,
      CHANNELS_APPROVED_USE,
      [],
      'allow',
      'public',
      [`approved-use::${approvedCat.id}`],
      [
        'Scope to approved user group and app instance before enabling.',
        'Place this policy BELOW all block/coach/alert policies in vendor console.',
      ],
    )
    outputs.push(wrapOutput(npj, 'approved-use', null, false, [], priority++))
  }

  return outputs
}
