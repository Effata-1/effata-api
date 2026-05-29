import type { NeutralPolicy, TranslationResult, VendorCapabilityRegistry } from '../types'
import { resolveAction } from '../types'

export const ADAPTER_VERSION = '1.0.0'

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

  // Build destination scope
  const destination: Record<string, unknown> = policy.scope_all_apps
    ? { app_categories: ['Generative AI'] }
    : { apps: policy.scope_app_ids }

  if (policy.scope_all_apps) {
    exactMappings.push('scope_all_apps → destination.app_categories: Generative AI')
  } else {
    exactMappings.push('scope_app_ids → destination.apps')
  }

  // For approved-use policies: emit a tightly-scoped Allow rule first (Netskope first-match top-down)
  if (policy.policy_type === 'approved-use' || policy.primary_action === 'allow') {
    const activities: string[] = []
    if (uploadAction === 'allow')     activities.push('Upload')
    if (postPromptAction === 'allow') activities.push('Post')
    if (downloadAction === 'allow')   activities.push('Download')
    if (activities.length === 0)      activities.push('Upload', 'Post')

    nativePolicies.push({
      name:          `[Allow] ${policy.name}`,
      policy_family: 'Real-time Protection',
      policy_type:   'Cloud App Access',
      destination,
      activities,
      action:        'Allow',
    })

    exactMappings.push('approved-use → Allow action')
    testsRequired.push(
      'Validate allow rule is scoped to approved app instance + approved user group to avoid bypassing downstream DLP controls.',
      'Verify policy order in Netskope console — Allow rule must sit above block/DLP rules for the same destination.',
    )
  }

  // Build the main enforcement/monitoring policy
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
  const actionsInUse = Object.values(actionMap).filter(a => a !== 'not-set')
  const primaryNativeAction = actionsInUse.includes('block') ? 'Block'
    : actionsInUse.some(a => a.startsWith('coach')) ? 'Coach'
    : actionsInUse.includes('alert') ? 'Alert'
    : actionsInUse.includes('monitor') ? 'Monitor'
    : 'Allow'

  const mainPolicy: Record<string, unknown> = {
    name:           `[DLP] ${policy.name}`,
    policy_family:  'Real-time Protection',
    policy_type:    'Cloud App Access',
    destination,
    activities,
    action:         primaryNativeAction,
  }

  if (policy.data_classification_label && policy.data_classification_label !== 'all') {
    mainPolicy['profile'] = `EFFATA-${policy.data_classification_label.toUpperCase().replace(/-/g, '_')}`
    exactMappings.push('data_classification_label → DLP profile name')
  }

  if (primaryNativeAction === 'Block' || primaryNativeAction === 'Alert') {
    mainPolicy['secondary_actions'] = ['Alert']
    mainPolicy['save_evidence']     = true
    exactMappings.push('block/alert → save_evidence: true')
  }

  if (primaryNativeAction === 'Coach') {
    mainPolicy['secondary_actions'] = ['UserNotification']
    exactMappings.push('coach → secondary_actions: UserNotification')
  }

  exactMappings.push('post_prompt → activity Post')
  exactMappings.push('upload → activity Upload')
  exactMappings.push('download → activity Download')
  exactMappings.push('primary_action → action')

  if (policy.rules.some(r => r.data_type.startsWith('clabel:'))) {
    lossyMappings.push('Sensitivity label conditions (clabel:) require tenant-specific enterprise-classification configuration in Netskope.')
    unverifiedAreas.push('Public-doc parity for generic label-condition syntax in Netskope.')
  }

  if (policy.policy_type === 'prohibited') {
    mainPolicy['action'] = 'Block'
    exactMappings.push('policy_type prohibited → action Block')
  }

  nativePolicies.push(mainPolicy)

  testsRequired.push(
    'Validate app category coverage includes all target AI apps.',
    'Validate DLP profile bindings for data classification labels.',
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
