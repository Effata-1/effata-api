import type { NeutralPolicy, TranslationResult, VendorCapabilityRegistry } from '../types'
import { resolveAction, actionToSeverity } from '../types'

export const ADAPTER_VERSION = '1.0.0'

/** Forcepoint has the cleanest 1:1 mapping of the four adapters */
export function translate(
  policy: NeutralPolicy,
  _registry: VendorCapabilityRegistry,
): TranslationResult {
  const exactMappings: string[]     = []
  const lossyMappings: string[]     = []
  const unsupportedIntent: string[] = []
  const unverifiedAreas: string[]   = []
  const testsRequired: string[]     = []

  // Resolve effective actions (rule-level beats policy-level)
  const uploadAction     = resolveAction(policy, 'upload')
  const postPromptAction = resolveAction(policy, 'post_prompt')
  const downloadAction   = resolveAction(policy, 'download')

  // Primary action for the policy (most restrictive across activities)
  const primaryAction = [uploadAction, postPromptAction, downloadAction]
    .filter(a => a !== 'not-set')
    .reduce((best, a) => {
      const actionRanks: Record<string, number> = {
        'not-set': 0, allow: 1, monitor: 2, alert: 3,
        coach: 4, 'coach-ack': 4, 'coach-just': 4, block: 5,
      }
      return (actionRanks[a] ?? 0) > (actionRanks[best] ?? 0) ? a : best
    }, policy.primary_action ?? 'monitor')

  // Source resources
  const sourceResources: string[] = ['All Users']
  exactMappings.push('identity_context/all users → source_resources')

  // Destination resources
  const destinationResources: string[] = policy.scope_all_apps
    ? ['GenAI application group or web destinations']
    : policy.scope_app_ids.length > 0
      ? policy.scope_app_ids
      : ['GenAI application group or web destinations']

  if (!policy.scope_all_apps && policy.scope_app_ids.length > 0) {
    exactMappings.push('scope_app_ids → destination_resources')
  } else {
    lossyMappings.push('scope_all_apps: true — GenAI app grouping is destination-definition dependent in Forcepoint. Define a Forcepoint destination group containing target AI apps.')
    testsRequired.push('Define a Forcepoint destination resource group containing all target GenAI apps (ChatGPT, Claude, Gemini, etc.).')
  }

  // Classifiers from data classification label + rules
  const classifiers: string[] = []
  if (policy.data_classification_label && policy.data_classification_label !== 'all') {
    classifiers.push(`Effata classification: ${policy.data_classification_label}`)
    exactMappings.push('data_classification_label → classifier')
  }
  for (const rule of policy.rules) {
    if (rule.data_type.startsWith('clabel:')) {
      classifiers.push('Customer sensitivity label — configure as Forcepoint data identifier')
      unverifiedAreas.push('Customer sensitivity label (clabel:) — tenant-specific MIP label parity requires Forcepoint configuration.')
    } else if (rule.data_type !== 'all' && !classifiers.includes(rule.data_type)) {
      classifiers.push(rule.data_type)
    }
  }
  if (classifiers.length === 0) classifiers.push('All data')
  exactMappings.push('rules[].data_type → classifiers')

  // Severity from resolved action
  const severity = actionToSeverity(primaryAction)
  exactMappings.push('primary_action → severity (block → Critical, coach → High, monitor → Medium, allow → Low)')

  // Forcepoint action
  let forcepointAction: string
  switch (primaryAction) {
    case 'block':
      forcepointAction = 'Block'
      exactMappings.push('block → action Block')
      break
    case 'coach':
    case 'coach-ack':
    case 'coach-just':
      forcepointAction = 'Coach'
      exactMappings.push('coach → action Coach with user notification')
      break
    case 'alert':
      forcepointAction = 'Alert'
      exactMappings.push('alert → action Alert')
      break
    case 'monitor':
      forcepointAction = 'Monitor'
      exactMappings.push('monitor → action Monitor (audit)')
      break
    case 'allow':
      forcepointAction = 'Allow'
      exactMappings.push('allow → action Allow')
      testsRequired.push(
        'Validate allow rule is scoped to approved destinations only to avoid bypassing downstream DLP controls.',
      )
      break
    default:
      forcepointAction = 'Monitor'
  }

  // Activities
  const activities: string[] = []
  if (uploadAction !== 'not-set')     activities.push('upload')
  if (postPromptAction !== 'not-set') activities.push('post/submit')
  if (downloadAction !== 'not-set')   activities.push('download')
  if (activities.length === 0)        activities.push('upload', 'post/submit')
  exactMappings.push('upload/post_prompt/download → Forcepoint activity types')

  const actions: string[] = [forcepointAction, 'Create Incident']
  if (primaryAction === 'block' || primaryAction === 'alert') {
    actions.push('Export Evidence')
    exactMappings.push('block/alert → Export Evidence')
  }

  const nativePolicy = {
    name:                  policy.name,
    description:           policy.description ?? undefined,
    source_resources:      sourceResources,
    destination_resources: destinationResources,
    classifiers,
    activities,
    severity,
    action:                actions,
  }

  const hasLossy = lossyMappings.length > 0

  return {
    vendor:          'forcepoint-dlp',
    status:          hasLossy ? 'partial' : 'success',
    native_policies: [nativePolicy],
    mapping_report: {
      exact_mappings:          exactMappings,
      lossy_mappings:          lossyMappings,
      unsupported_intent:      unsupportedIntent,
      unverified_vendor_areas: unverifiedAreas,
      tests_required:          testsRequired,
    },
  }
}
