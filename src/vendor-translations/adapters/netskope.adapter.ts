import type { NeutralPolicy, TranslationResult, VendorCapabilityRegistry } from '../types'
import { resolveAction } from '../types'

export const ADAPTER_VERSION = '1.2.0'

function toNetskopeAction(effataAction: string): string {
  switch (effataAction) {
    case 'block':                  return 'Block'
    case 'coach':
    case 'coach-ack':
    case 'coach-just':             return 'Coach'
    case 'alert':                  return 'Alert'
    case 'monitor':                return 'Allow'   // Netskope has no Monitor action — Allow + save_evidence
    case 'allow':                  return 'Allow'
    default:                       return 'Allow'
  }
}

function toSeverity(effataAction: string): string {
  switch (effataAction) {
    case 'block':                  return 'Critical'
    case 'coach':
    case 'coach-ack':
    case 'coach-just':
    case 'alert':                  return 'High'
    case 'monitor':                return 'Medium'
    default:                       return 'Low'
  }
}

function dlpProfileName(label: string | null): string | null {
  if (!label || label === 'all') return null
  return `EFFATA-${label.toUpperCase().replace(/-/g, '_')}`
}

export function translate(
  policy: NeutralPolicy,
  _registry: VendorCapabilityRegistry,
): TranslationResult {
  const exactMappings: string[]      = []
  const lossyMappings: string[]      = []
  const unsupportedIntent: string[]  = []
  const unverifiedAreas: string[]    = []
  const testsRequired: string[]      = []

  const nativePolicies: object[] = []

  // Resolve effective actions per activity (rule-level beats policy-level)
  const postPromptAction = resolveAction(policy, 'post_prompt')
  const uploadAction     = resolveAction(policy, 'upload')
  const downloadAction   = resolveAction(policy, 'download')

  // Source scope — default to All Users; customer must remap to specific groups
  const source = { users_or_groups: ['All Users'] }
  lossyMappings.push(
    'source defaulted to "All Users" — remap to specific user groups or OUs in Netskope console before enabling.',
  )

  // Build destination scope
  // When scope_all_apps is false but no specific apps listed, fall back to Generative AI category
  let destination: Record<string, unknown>
  if (policy.scope_all_apps) {
    destination = { app_categories: ['Generative AI'] }
    exactMappings.push('scope_all_apps → destination.app_categories: Generative AI')
  } else if (policy.scope_app_ids.length > 0) {
    destination = { apps: policy.scope_app_ids }
    exactMappings.push('scope_app_ids → destination.apps')
  } else {
    destination = { app_categories: ['Generative AI'] }
    lossyMappings.push('No specific apps scoped — destination defaulted to Generative AI app category. Define specific app instances in Netskope if needed.')
  }

  // DLP profile reference
  const profileName = dlpProfileName(policy.data_classification_label)
  if (profileName) {
    exactMappings.push(`data_classification_label → dlp_profile: ${profileName} (must exist in Netskope tenant)`)
    testsRequired.push(
      `Create or verify DLP profile "${profileName}" exists in Netskope (Policies → DLP Profiles) and matches the intended data patterns for "${policy.data_classification_label}".`,
    )
  } else {
    // No classification label — policy matches ALL content for the specified activities
    lossyMappings.push('No data_classification_label set — dlp_profile is null, meaning this policy matches ALL content for the specified activities. Add a DLP profile if content inspection is required.')
  }

  // For approved-use: emit a tightly-scoped Allow rule first (Netskope first-match top-down)
  if (policy.policy_type === 'approved-use' || policy.primary_action === 'allow') {
    const allowActivities: string[] = []
    if (uploadAction === 'allow')     allowActivities.push('Upload')
    if (postPromptAction === 'allow') allowActivities.push('Post')
    if (downloadAction === 'allow')   allowActivities.push('Download')
    if (allowActivities.length === 0) allowActivities.push('Upload', 'Post')

    nativePolicies.push({
      name:                `[Allow] ${policy.name}`,
      status:              'enabled',
      source,
      destination,
      activities:          allowActivities,
      action:              'Allow',
      severity:            'Low',
      alert:               false,
      save_evidence:       false,
      notification_template: null,
      policy_type:         'Cloud App Access',
      policy_family:       'Real-time Protection',
    })

    exactMappings.push('approved-use → Allow action')
    testsRequired.push(
      'Validate allow rule is scoped to an approved app instance + approved user group — a broad Allow above DLP rules can bypass all downstream controls.',
      'Verify policy order in Netskope console — this Allow rule must sit above block/DLP rules for the same destination.',
    )
  }

  // Build activities list for the main enforcement policy
  const activities: string[] = []
  const actionMap: Record<string, string> = {}

  if (postPromptAction !== 'not-set') {
    activities.push('Post')
    actionMap['Post'] = postPromptAction
  }
  if (uploadAction !== 'not-set') {
    activities.push('Upload')
    actionMap['Upload'] = uploadAction
  }
  if (downloadAction !== 'not-set') {
    activities.push('Download')
    actionMap['Download'] = downloadAction
  }
  if (activities.length === 0) activities.push('Upload', 'Post')

  // Determine primary native action (most restrictive across resolved activities)
  const actionsInUse    = Object.values(actionMap).filter(a => a !== 'not-set')
  const mostRestrictive = actionsInUse.includes('block') ? 'block'
    : actionsInUse.some(a => a.startsWith('coach'))      ? 'coach'
    : actionsInUse.includes('alert')                     ? 'alert'
    : actionsInUse.includes('monitor')                   ? 'monitor'
    : 'allow'

  const primaryNativeAction = toNetskopeAction(mostRestrictive)
  const severity            = toSeverity(mostRestrictive)

  // Netskope has no "Monitor" action — Allow + save_evidence is the equivalent
  if (mostRestrictive === 'monitor') {
    lossyMappings.push('monitor action mapped to Allow + save_evidence: true (Netskope has no dedicated Monitor action).')
  }

  const saveEvidence = mostRestrictive === 'block' || mostRestrictive === 'alert' || mostRestrictive === 'monitor'
  const alert        = mostRestrictive === 'block' || mostRestrictive === 'alert'

  const notificationTemplate: string | null = mostRestrictive.startsWith('coach')
    ? 'EFFATA-COACH-NOTIFICATION'
    : null

  const mainPolicy: Record<string, unknown> = {
    name:                  `[DLP] ${policy.name}`,
    status:                'enabled',
    source,
    destination,
    activities,
    dlp_profile:           profileName,
    action:                primaryNativeAction,
    severity,
    alert,
    save_evidence:         saveEvidence,
    notification_template: notificationTemplate,
    policy_type:           'Cloud App Access',
    policy_family:         'Real-time Protection',
  }

  if (primaryNativeAction === 'Block' || primaryNativeAction === 'Alert') {
    exactMappings.push('block/alert → alert: true, save_evidence: true')
  }
  if (primaryNativeAction === 'Coach') {
    exactMappings.push('coach → notification_template: EFFATA-COACH-NOTIFICATION (must exist in Netskope)')
    testsRequired.push(
      'Create or verify user notification template "EFFATA-COACH-NOTIFICATION" in Netskope (Policies → User Notifications) with the correct coaching message.',
    )
  }

  exactMappings.push('post_prompt → activity Post')
  exactMappings.push('upload → activity Upload')
  exactMappings.push('download → activity Download')
  exactMappings.push('primary_action → action')
  exactMappings.push('primary_action → severity')

  if (policy.policy_type === 'prohibited') {
    mainPolicy['action']   = 'Block'
    mainPolicy['severity'] = 'Critical'
    exactMappings.push('policy_type prohibited → action Block, severity Critical')
  }

  if (policy.rules.some(r => r.data_type.startsWith('clabel:'))) {
    lossyMappings.push('Sensitivity label conditions (clabel:) require tenant-specific enterprise-classification profile in Netskope — cannot be auto-created.')
    unverifiedAreas.push('Public-doc parity for generic label-condition syntax in Netskope.')
  }

  nativePolicies.push(mainPolicy)

  testsRequired.push(
    'Validate Netskope app category "Generative AI" covers all target AI apps in your tenant (Netskope categories may not include newer apps).',
  )

  const hasLossy = lossyMappings.length > 0
  const status: TranslationResult['status'] = hasLossy ? 'partial' : 'success'

  return {
    vendor: 'netskope',
    status,
    native_policies:  nativePolicies,
    mapping_report: {
      exact_mappings:          exactMappings,
      lossy_mappings:          lossyMappings,
      unsupported_intent:      unsupportedIntent,
      unverified_vendor_areas: unverifiedAreas,
      tests_required:          testsRequired,
    },
  }
}
