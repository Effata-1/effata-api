import type { NeutralPolicy, OrgVendorObjectMapping, TranslationResult, VendorCapabilityRegistry } from '../types'
import { resolveAction } from '../types'
import { validateNeutralPolicy } from '../../neutral-policies/schema'

export const ADAPTER_VERSION = '1.0.0'

/** Purview always requires a policy bundle — one neutral policy → multiple location-specific policies */
export function translate(
  policy: NeutralPolicy,
  _registry: VendorCapabilityRegistry,
  _mappings: OrgVendorObjectMapping[] = [],
): TranslationResult {
  const exactMappings: string[]     = []
  const lossyMappings: string[]     = []
  const unsupportedIntent: string[] = []
  const unverifiedAreas: string[]   = []
  const testsRequired: string[]     = []

  const nativePolicies: object[] = []

  // npj-first: use structured neutral policy when valid
  const npj = policy.neutral_policy_json
    ? validateNeutralPolicy(policy.neutral_policy_json)
    : null
  if (policy.neutral_policy_json && Object.keys(policy.neutral_policy_json).length > 0 && !npj) {
    lossyMappings.push('neutral_policy_json failed schema validation — translated from legacy fields only. Re-generate policies for better accuracy.')
  }

  const postPromptAction = npj
    ? (npj.scope.activities.includes('post') || npj.scope.activities.includes('prompt_submit') ? npj.decision.mode : 'not-set')
    : resolveAction(policy, 'post_prompt')
  const uploadAction = npj
    ? (npj.scope.activities.includes('upload') ? npj.decision.mode : 'not-set')
    : resolveAction(policy, 'upload')
  const downloadAction = npj
    ? (npj.scope.activities.includes('download') ? npj.decision.mode : 'not-set')
    : resolveAction(policy, 'download')

  if (npj) {
    exactMappings.push('npj.scope.activities → Purview location activities (exact)')
    exactMappings.push('npj.decision.mode → Purview action (exact)')
  }

  const purviewAction = (action: string): string => {
    switch (action) {
      case 'block':                         return 'Block'
      case 'coach':
      case 'coach-ack':
      case 'coach-just':
      case 'alert':                         return 'UserNotification'
      case 'monitor':                       return 'GenerateIncidentReport'
      case 'allow':                         return 'Allow'
      default:                              return 'GenerateIncidentReport'
    }
  }

  const userScope = policy.scope_all_apps ? 'All Users' : 'Scoped Users'

  const contentConditions: string[] = []
  if (npj && npj.content.conditions.length > 0) {
    for (const cond of npj.content.conditions) {
      if (cond.type === 'data_type') {
        contentConditions.push(`Sensitivity: ${cond.sensitivity} (${cond.name})`)
        exactMappings.push(`npj data_type condition [${cond.sensitivity}] → SIT or sensitivity label condition`)
      } else if (cond.type === 'classification_label') {
        contentConditions.push(`Classification label: ${cond.label_name} (${cond.label_source})`)
        exactMappings.push('npj classification_label condition → AIP/sensitivity label condition')
      } else if (cond.type === 'filename') {
        contentConditions.push(`Filename pattern: ${cond.pattern}`)
        lossyMappings.push('Filename pattern conditions — Purview does not natively support glob-based filename matching; use SIT or keyword rules instead.')
      }
    }
  } else {
    if (policy.data_classification_label && policy.data_classification_label !== 'all') {
      contentConditions.push(`Sensitivity label: ${policy.data_classification_label}`)
      exactMappings.push('data_classification_label → sensitivity label condition (where location supports it)')
    }
    for (const rule of policy.rules) {
      if (rule.data_type.startsWith('clabel:')) {
        contentConditions.push('Customer sensitivity label (clabel:) — requires EDM or AIP label mapping')
      } else if (!contentConditions.includes(rule.data_type)) {
        contentConditions.push(rule.data_type)
      }
    }
  }
  if (contentConditions.length === 0) contentConditions.push('All content')

  exactMappings.push('users/groups → policy scope')
  exactMappings.push('sensitivity labels → sensitivity label conditions (Exchange, SharePoint, OneDrive, Devices)')

  // 1. Devices location — covers endpoint upload/download
  if (uploadAction !== 'not-set' || downloadAction !== 'not-set') {
    nativePolicies.push({
      name:               `[Devices] ${policy.name}`,
      location:           'Devices',
      scope:              { users_or_groups: [userScope] },
      content_conditions: contentConditions,
      action:             purviewAction(uploadAction !== 'not-set' ? uploadAction : downloadAction),
    })
    exactMappings.push('upload/download → Devices location')
  }

  // 2. Managed Cloud Apps / Instances location
  nativePolicies.push({
    name:               `[Cloud Apps] ${policy.name}`,
    location:           'Instances',
    scope:              { users_or_groups: [userScope] },
    content_conditions: contentConditions,
    action:             purviewAction(uploadAction !== 'not-set' ? uploadAction : (policy.primary_action ?? 'monitor')),
    notes:              'Covers managed cloud app instances (e.g. Teams, SharePoint in scope).',
  })
  exactMappings.push('scope → Instances location for managed cloud apps')

  // 3. Exchange / SharePoint / OneDrive location
  nativePolicies.push({
    name:               `[Exchange/SharePoint/OneDrive] ${policy.name}`,
    locations:          ['Exchange', 'SharePoint', 'OneDrive', 'Teams'],
    scope:              { users_or_groups: [userScope] },
    content_conditions: contentConditions,
    action:             purviewAction(policy.primary_action ?? 'monitor'),
  })
  exactMappings.push('M365 locations → Exchange/SharePoint/OneDrive/Teams')

  // 4. Copilot (preview) — post_prompt maps here; marked unverified per research doc
  if (postPromptAction !== 'not-set') {
    nativePolicies.push({
      name:     `[Copilot] ${policy.name}`,
      location: 'Microsoft 365 Copilot',
      scope:    { users_or_groups: [userScope] },
      action:   purviewAction(postPromptAction),
      notes:    'UNVERIFIED — validate whether prompt protection in this tenant is SIT-driven, label-driven, or both before deploying.',
    })
    unverifiedAreas.push(
      'Microsoft 365 Copilot location: Microsoft docs are internally inconsistent on whether prompt protection is SIT-driven or label-driven. Requires tenant empirical validation.',
    )
    testsRequired.push('Tenant validation for Copilot prompt policy semantics before production deployment.')
  }

  // Coaching mapping is partial in Purview
  const hasCoaching = policy.rules.some(r =>
    r.post_prompt.startsWith('coach') || r.upload.startsWith('coach') || r.download.startsWith('coach')
  ) || (policy.primary_action ?? '').startsWith('coach')

  if (hasCoaching) {
    lossyMappings.push('Coaching actions (coach/coach-ack/coach-just) map to UserNotification in Purview, but availability varies by location.')
  }

  // Allow policies need scoping warning
  if ((npj ? npj.intent === 'allow_approved_use' : false) || policy.policy_type === 'approved-use' || policy.primary_action === 'allow') {
    unverifiedAreas.push(
      'Allow policy: validate scope includes approved app instance, approved user group, and approved tenant. Policy bundle order must be reviewed in Purview compliance portal.',
    )
    testsRequired.push(
      'Validate allow scope is tightly defined to prevent inadvertently bypassing DLP controls across M365 locations.',
    )
  }

  lossyMappings.push(
    'One neutral policy maps to a Purview location bundle (Devices + Cloud Apps + M365 + Copilot) — review each location policy individually.',
    'App-category targeting is weaker than in SSE-native vendors (Netskope/Skyhigh).',
  )
  testsRequired.push(
    'Browser/network control validation for unmanaged AI apps.',
    'Verify Purview E3 vs E5 licensing for Devices and Insider Risk features.',
  )

  exactMappings.push('block → Block action across all locations')

  return {
    vendor:                   'microsoft-purview',
    catalog_version:          '',
    customer_mapping_version: '',
    status:                   'partial',
    native_policies:          nativePolicies,
    mapping_report: {
      exact_mappings:            exactMappings,
      lossy_mappings:            lossyMappings,
      unsupported_intent:        unsupportedIntent,
      unverified_vendor_areas:   unverifiedAreas,
      tests_required:            testsRequired,
      customer_mapping_required: [],
    },
  }
}
