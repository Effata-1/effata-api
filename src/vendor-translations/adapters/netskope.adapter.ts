import type { NeutralPolicy, TranslationResult, VendorCapabilityRegistry } from '../types'
import { resolveAction } from '../types'

export const ADAPTER_VERSION = '3.0.0'

function toNetskopeAction(effataAction: string): string {
  switch (effataAction) {
    case 'block':                  return 'Block'
    case 'coach':
    case 'coach-ack':
    case 'coach-just':             return 'Coach'
    case 'alert':                  return 'Alert'
    case 'monitor':                return 'Allow'  // Netskope has no Monitor — Allow is the closest equivalent
    case 'allow':                  return 'Allow'
    default:                       return 'Allow'
  }
}

function policyGroup(action: string): string {
  if (action === 'Allow') return '1. Header Policies'
  if (action === 'Block' || action === 'Coach' || action === 'Alert') return '2. DLP Policies'
  return '3. Monitoring Policies'
}

function dlpProfileName(label: string | null): string | null {
  if (!label || label === 'all') return null
  return `EFFATA-${label.toUpperCase().replace(/-/g, '_')}`
}

export function translate(
  policy: NeutralPolicy,
  _registry: VendorCapabilityRegistry,
): TranslationResult {
  const exactMappings: string[]     = []
  const lossyMappings: string[]     = []
  const unsupportedIntent: string[] = []
  const unverifiedAreas: string[]   = []
  const testsRequired: string[]     = []
  const nativePolicies: object[]    = []

  // Resolve effective actions per activity (rule-level beats policy-level)
  const postPromptAction = resolveAction(policy, 'post_prompt')
  const uploadAction     = resolveAction(policy, 'upload')
  const downloadAction   = resolveAction(policy, 'download')
  const responseAction   = resolveAction(policy, 'response')

  // Netskope RT policies do not have a "Response" activity — only Post/Upload/Download.
  // AI output protection requires Netskope AI Access Security or a separate Download DLP policy.
  if (responseAction !== 'not-set') {
    unsupportedIntent.push(
      `response activity action "${responseAction}" cannot be mapped — Netskope Real-time Protection policies ` +
      `do not intercept AI-generated responses. For AI output protection, use Netskope AI Access Security ` +
      `(separate product capability) or a Download activity policy to inspect content returned from the AI app.`,
    )
  }

  // Source — default to All Users
  const source = { users_or_groups: ['All Users'] }
  lossyMappings.push(
    'source defaulted to "All Users" — remap to specific user groups or OUs in Netskope console before enabling.',
  )

  // Destination category/apps
  let destTarget: Record<string, string | string[]>
  if (policy.scope_all_apps) {
    destTarget = { category: 'Generative AI' }
    exactMappings.push('scope_all_apps → destination category: Generative AI')
  } else if (policy.scope_app_ids.length > 0) {
    destTarget = { specific_apps: policy.scope_app_ids }
    exactMappings.push('scope_app_ids → destination specific_apps')
  } else {
    destTarget = { category: 'Generative AI' }
    lossyMappings.push('No specific apps scoped — destination defaulted to Generative AI category. Define specific app instances in Netskope if needed.')
  }

  // Activities list
  const activities: string[] = []
  const actionMap: Record<string, string> = {}

  if (postPromptAction !== 'not-set') { activities.push('Post');     actionMap['Post']     = postPromptAction }
  if (uploadAction     !== 'not-set') { activities.push('Upload');   actionMap['Upload']   = uploadAction     }
  if (downloadAction   !== 'not-set') { activities.push('Download'); actionMap['Download'] = downloadAction   }
  if (activities.length === 0) activities.push('Upload', 'Post')

  exactMappings.push('post_prompt → activity Post')
  exactMappings.push('upload → activity Upload')
  exactMappings.push('download → activity Download')

  // Destination = target + activities (matches Netskope UI layout)
  const destination = { ...destTarget, activities }

  // Determine primary native action
  const actionsInUse    = Object.values(actionMap).filter(a => a !== 'not-set')
  const mostRestrictive = actionsInUse.includes('block')                   ? 'block'
    : actionsInUse.some(a => a.startsWith('coach'))                        ? 'coach'
    : actionsInUse.includes('alert')                                       ? 'alert'
    : actionsInUse.includes('monitor')                                     ? 'monitor'
    : 'allow'

  let primaryNativeAction = toNetskopeAction(mostRestrictive)

  if (mostRestrictive === 'monitor') {
    lossyMappings.push('monitor mapped to Allow (Netskope has no Monitor action — policy will Allow traffic; add an alert profile if visibility is needed).')
  }

  // DLP profile
  const profileName = dlpProfileName(policy.data_classification_label)
  if (profileName) {
    exactMappings.push(`data_classification_label → DLP profile: ${profileName} (must exist in Netskope tenant)`)
    testsRequired.push(
      `Create or verify DLP profile "${profileName}" exists in Netskope (Policies → DLP Profiles) and matches the data patterns for "${policy.data_classification_label}".`,
    )
  } else {
    lossyMappings.push('No data_classification_label — no DLP profile configured. This policy acts on ALL content for the specified activities. Add a DLP profile if content inspection is required.')
  }

  // Notification template for coach
  const notificationTemplate: string | null = mostRestrictive.startsWith('coach')
    ? 'EFFATA-COACH-NOTIFICATION'
    : null
  if (notificationTemplate) {
    exactMappings.push('coach → notification_template: EFFATA-COACH-NOTIFICATION')
    testsRequired.push(
      'Create or verify user notification template "EFFATA-COACH-NOTIFICATION" in Netskope (Policies → User Notifications).',
    )
  }

  exactMappings.push('primary_action → profile action')

  if (policy.policy_type === 'prohibited') {
    primaryNativeAction = 'Block'
    exactMappings.push('policy_type prohibited → action Block')
  }

  // Profile & Action — Netskope simple form: one action for all DLP profiles.
  // The per-profile table ("Set action for each profile") is only needed when different
  // profiles require different actions — not the case here.
  const profileAction = profileName
    ? { dlp_profiles: [profileName], action: primaryNativeAction, notification_template: notificationTemplate }
    : null

  // Traffic Action ("+ ADD TRAFFIC ACTION" in Netskope) is NOT a default.
  // It only applies when there is a specific requirement to take action on traffic
  // that doesn't match any configured DLP profile.
  // Customers should decide whether to add this in the Netskope console based on their
  // visibility requirements. See tests_required below.
  testsRequired.push(
    'Optionally configure a Traffic Action in Netskope (+ ADD TRAFFIC ACTION) if you want to Alert or Block ' +
    'on traffic that does not match any of the configured DLP profiles. Leave unset if downstream policies cover this.',
  )

  // For approved-use: emit a tightly-scoped Allow policy first (top-down first-match).
  // No traffic action on Allow policies — the Allow itself is the intended action.
  if (policy.policy_type === 'approved-use' || policy.primary_action === 'allow') {
    const allowActivities: string[] = []
    if (uploadAction === 'allow')     allowActivities.push('Upload')
    if (postPromptAction === 'allow') allowActivities.push('Post')
    if (downloadAction === 'allow')   allowActivities.push('Download')
    if (allowActivities.length === 0) allowActivities.push('Upload', 'Post')

    nativePolicies.push({
      name:          `[Allow] ${policy.name}`,
      status:        'enabled',
      source,
      destination:   { ...destTarget, activities: allowActivities },
      profile_action: null,
      action:        'Allow',
      group:         '1. Header Policies',
      policy_type:   'Cloud App Access',
      policy_family: 'Real-time Protection',
    })
    exactMappings.push('approved-use → Allow action')
    testsRequired.push(
      'Validate Allow rule is scoped to an approved app instance + approved user group to avoid bypassing downstream DLP controls.',
      'Verify policy order in Netskope console — this Allow rule must sit above block/DLP rules for the same destination.',
    )
  }

  if (policy.rules.some(r => r.data_type.startsWith('clabel:'))) {
    lossyMappings.push('Sensitivity label conditions (clabel:) require tenant-specific enterprise-classification profile in Netskope — cannot be auto-created.')
    unverifiedAreas.push('Public-doc parity for generic label-condition syntax in Netskope.')
  }

  nativePolicies.push({
    name:          `[DLP] ${policy.name}`,
    status:        'enabled',
    source,
    destination,
    profile_action: profileAction,
    group:         policyGroup(primaryNativeAction),
    policy_type:   'Cloud App Access',
    policy_family: 'Real-time Protection',
  })

  testsRequired.push(
    'Validate Netskope app category "Generative AI" covers all target AI apps in your tenant.',
  )

  return {
    vendor:  'netskope',
    status:  lossyMappings.length > 0 ? 'partial' : 'success',
    native_policies: nativePolicies,
    mapping_report: {
      exact_mappings:          exactMappings,
      lossy_mappings:          lossyMappings,
      unsupported_intent:      unsupportedIntent,
      unverified_vendor_areas: unverifiedAreas,
      tests_required:          testsRequired,
    },
  }
}
