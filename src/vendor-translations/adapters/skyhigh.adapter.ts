import type { NeutralPolicy, TranslationResult, VendorCapabilityRegistry } from '../types'
import { resolveAction, actionToSeverity } from '../types'

export const ADAPTER_VERSION = '1.0.0'

/** Skyhigh always emits two native policies: Inline Proxy + API-driven */
export function translate(
  policy: NeutralPolicy,
  _registry: VendorCapabilityRegistry,
): TranslationResult {
  const exactMappings: string[]     = []
  const lossyMappings: string[]     = []
  const unsupportedIntent: string[] = []
  const unverifiedAreas: string[]   = []
  const testsRequired: string[]     = []

  const postPromptAction = resolveAction(policy, 'post_prompt')
  const uploadAction     = resolveAction(policy, 'upload')
  const downloadAction   = resolveAction(policy, 'download')
  const responseAction   = resolveAction(policy, 'response')

  // Build conditions from data types
  const conditions: string[] = []
  if (policy.data_classification_label && policy.data_classification_label !== 'all') {
    conditions.push(`Classification: ${policy.data_classification_label}`)
    exactMappings.push('data_classification_label → rule condition')
  }
  for (const rule of policy.rules) {
    if (rule.data_type.startsWith('clabel:')) {
      conditions.push('AIP/Purview label metadata → Document Property Classification')
      exactMappings.push('clabel: sensitivity label → document property classification (AIP/Purview label metadata)')
    } else if (!conditions.some(c => c.includes(rule.data_type))) {
      conditions.push(rule.data_type)
    }
  }
  if (conditions.length === 0) conditions.push('All content')
  exactMappings.push('rules[].data_type → rule conditions')

  // Service/app scope
  const services: string[] = policy.scope_all_apps
    ? ['All Generative AI applications']
    : policy.scope_app_ids.length > 0
      ? policy.scope_app_ids
      : ['All Generative AI applications']

  if (policy.scope_all_apps) {
    exactMappings.push('scope_all_apps → all GenAI services in scope')
  } else {
    exactMappings.push('scope_app_ids → services list')
  }

  // Inline proxy action (upload / post_prompt)
  const inlineAction     = uploadAction !== 'not-set' ? uploadAction : (postPromptAction !== 'not-set' ? postPromptAction : (policy.primary_action ?? 'monitor'))
  const inlineSeverity   = actionToSeverity(inlineAction)
  const inlineNativeAct  = inlineAction === 'block' ? 'Block'
    : inlineAction.startsWith('coach') ? 'Coach + Incident'
    : inlineAction === 'alert' ? 'Alert + Incident'
    : 'GenerateIncidentReport'

  const inlineActions: string[] = [inlineNativeAct]
  if (inlineAction === 'block' || inlineAction === 'alert') {
    inlineActions.push('Incident', 'Save Evidence')
    exactMappings.push('block/alert → Save Evidence in inline proxy')
  }
  if (inlineAction.startsWith('coach')) {
    inlineActions.push('User Coaching Notification')
  }

  exactMappings.push('upload/post_prompt → Inline Proxy mode actions')
  exactMappings.push('severity mapping: block → Critical, coach → High, monitor → Medium, allow → Low')

  // Policy 1: Shadow/Web DLP — Inline Proxy
  const inlinePolicy = {
    name:        `[Inline Proxy] ${policy.name}`,
    mode:        'Inline Proxy (Shadow/Web DLP)',
    description: policy.description ?? undefined,
    scope: {
      services,
      activities: ['upload', 'post/prompt'],
    },
    rule_groups: [
      {
        severity:   inlineSeverity,
        conditions,
        actions:    inlineActions,
      },
    ],
  }

  // API-driven action (download / response — at-rest or near-real-time)
  const apiAction    = downloadAction !== 'not-set' ? downloadAction : (responseAction !== 'not-set' ? responseAction : (policy.primary_action ?? 'monitor'))
  const apiSeverity  = actionToSeverity(apiAction)
  const apiNativeAct = apiAction === 'block' ? 'Quarantine'
    : apiAction.startsWith('coach') ? 'Coach + Incident'
    : apiAction === 'alert' ? 'Alert + Incident'
    : 'Incident'

  const apiActions: string[] = [apiNativeAct, 'Monitor']
  if (apiAction.startsWith('coach')) {
    apiActions.push('Apply Classification Label where supported')
  }

  exactMappings.push('download/response → API-driven mode actions')

  // Enterprise AI apps for API mode
  const enterpriseApps: string[] = policy.scope_all_apps
    ? ['Microsoft 365 Copilot Enterprise', 'ChatGPT Enterprise']
    : services

  // Policy 2: API-driven (Sanctioned DLP)
  const apiPolicy = {
    name:        `[API-driven] ${policy.name}`,
    mode:        'API-driven (Sanctioned DLP)',
    description: policy.description ?? undefined,
    scope: {
      services: enterpriseApps,
      activities: ['download', 'response'],
    },
    rule_groups: [
      {
        severity:   apiSeverity,
        conditions,
        actions:    apiActions,
      },
    ],
  }

  // Coaching availability is partial in Skyhigh
  const hasCoaching = [uploadAction, postPromptAction, downloadAction, policy.primary_action ?? ''].some(a => a.startsWith('coach'))
  if (hasCoaching) {
    lossyMappings.push('Coaching actions map to user coaching notification; availability depends on Skyhigh SSE mode and app configuration.')
  }

  // Allow policy warning
  if (policy.policy_type === 'approved-use' || policy.primary_action === 'allow') {
    unverifiedAreas.push('Allow policy: validate scope is tightly defined to sanctioned apps and approved users to avoid bypassing inline DLP controls.')
    testsRequired.push('Verify allow rule does not create a gap in Shadow/Web DLP coverage for unsanctioned AI apps.')
  }

  lossyMappings.push('One neutral policy split into Inline Proxy policy + API-driven policy — review both outputs independently.')
  if (policy.scope_all_apps) {
    lossyMappings.push('Endpoint DLP coverage for Skyhigh is unverified in public documentation — validate endpoint parity separately.')
    unverifiedAreas.push('Native endpoint DLP parity for Skyhigh Security.')
  }

  testsRequired.push(
    'Validate inline proxy coverage for all target AI apps.',
    'Validate API-driven mode connectivity for enterprise AI services.',
  )

  return {
    vendor:          'skyhigh-security',
    status:          'partial',
    native_policies: [inlinePolicy, apiPolicy],
    mapping_report: {
      exact_mappings:          exactMappings,
      lossy_mappings:          lossyMappings,
      unsupported_intent:      unsupportedIntent,
      unverified_vendor_areas: unverifiedAreas,
      tests_required:          testsRequired,
    },
  }
}
