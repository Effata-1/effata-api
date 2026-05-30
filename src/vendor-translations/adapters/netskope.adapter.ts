import type { NeutralPolicy, TranslationResult, VendorCapabilityRegistry } from '../types'
import { resolveAction } from '../types'
import { validateNeutralPolicy } from '../../neutral-policies/schema'

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

function dlpProfileName(label: string): string {
  return `EFFATA-${label.toUpperCase().replace(/-/g, '_')}`
}

/**
 * Derive DLP profile names for a policy.
 * Priority: data_classification_label → rule data_type prefixes → none.
 * Returns { profiles, fromRules } so the caller can add appropriate mapping notes.
 */
function inferDlpProfiles(
  policy: NeutralPolicy,
): { profiles: string[]; source: 'label' | 'rules' | 'none' } {
  // Priority 1: explicit classification label
  if (policy.data_classification_label && policy.data_classification_label !== 'all') {
    return { profiles: [dlpProfileName(policy.data_classification_label)], source: 'label' }
  }

  // Priority 2: infer from rule data_type prefixes (e.g. "secret:api-key" → EFFATA-SECRET)
  const prefixes = new Set<string>()
  for (const rule of policy.rules) {
    const dt = rule.data_type
    if (!dt || dt === 'all') continue
    if (dt.startsWith('clabel:')) continue  // label conditions — separate handling
    const prefix = dt.includes(':') ? dt.split(':')[0] : dt
    if (prefix) prefixes.add(prefix)
  }

  if (prefixes.size > 0) {
    return {
      profiles: [...prefixes].map(p => dlpProfileName(p)),
      source: 'rules',
    }
  }

  return { profiles: [], source: 'none' }
}

function generateDescription(
  action: string,
  activities: string[],
  label: string | null,
  dest: Record<string, string | string[]>,
): string {
  const actStr = activities.length === 0 ? 'traffic'
    : activities.length === 1 ? activities[0].toLowerCase()
    : activities.slice(0, -1).map(a => a.toLowerCase()).join(', ') + ' and ' + activities[activities.length - 1].toLowerCase()

  const dataStr = label ? `${label} data` : 'all content'

  const specificApps = dest.specific_apps as string[] | undefined
  const destStr = specificApps && specificApps.length > 0
    ? specificApps.slice(0, 3).join(', ') + (specificApps.length > 3 ? ` +${specificApps.length - 3} more` : '')
    : 'all GenAI apps'

  switch (action) {
    case 'Block':  return `Block ${actStr} of ${dataStr} to ${destStr}.`
    case 'Coach':  return `Coach users before ${actStr} of ${dataStr} to ${destStr}.`
    case 'Alert':  return `Alert on ${actStr} of ${dataStr} to ${destStr}.`
    case 'Allow':  return `Permit access to ${destStr}. Scope to approved app instances and user groups before enabling.`
    default:       return `Apply ${action.toLowerCase()} on ${actStr} of ${dataStr} to ${destStr}.`
  }
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

  // ── Neutral policy JSON — use as primary source when valid ────────────────
  const npj = policy.neutral_policy_json
    ? validateNeutralPolicy(policy.neutral_policy_json)
    : null

  if (policy.neutral_policy_json && Object.keys(policy.neutral_policy_json).length > 0 && !npj) {
    lossyMappings.push(
      'neutral_policy_json failed schema validation — translated from legacy fields only. Re-generate policies for better accuracy.',
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

  // ── Activities and primary action ─────────────────────────────────────────
  const activities: string[] = []
  let mostRestrictive: string

  if (npj) {
    // npj-first: activities come directly from structured scope — no guessing
    // browse + login map to Netskope "Browse" — blocks URL-level access (govern_app_access use case)
    if (npj.scope.activities.includes('browse') || npj.scope.activities.includes('login')) activities.push('Browse')
    if (npj.scope.activities.includes('post') || npj.scope.activities.includes('prompt_submit')) activities.push('Post')
    if (npj.scope.activities.includes('upload'))   activities.push('Upload')
    if (npj.scope.activities.includes('download')) activities.push('Download')
    if (activities.length === 0) activities.push('Upload', 'Post')

    // Map npj.decision.mode to effective action code
    const decisionMode = npj.decision.mode
    mostRestrictive = decisionMode === 'coach' && npj.decision.require_justification  ? 'coach-just'
      : decisionMode === 'coach' && npj.decision.require_acknowledgement              ? 'coach-ack'
      : decisionMode

    exactMappings.push('npj.scope.activities → Netskope activities (browse/login → Browse, post/prompt_submit → Post, upload → Upload, download → Download)')
    exactMappings.push('npj.decision.mode → Netskope action (exact, no inference)')

    // Preserve evidence note
    if (npj.decision.preserve_evidence) {
      exactMappings.push('npj.decision.preserve_evidence → Save Evidence enabled')
    }
  } else {
    // Legacy path: resolve from rules/primary_action
    const postPromptAction = resolveAction(policy, 'post_prompt')
    const uploadAction     = resolveAction(policy, 'upload')
    const downloadAction   = resolveAction(policy, 'download')
    const responseAction   = resolveAction(policy, 'response')

    if (responseAction !== 'not-set') {
      unsupportedIntent.push(
        `response activity action "${responseAction}" cannot be mapped — Netskope Real-time Protection policies ` +
        `do not intercept AI-generated responses. For AI output protection, use Netskope AI Access Security ` +
        `(separate product capability) or a Download activity policy to inspect content returned from the AI app.`,
      )
    }

    const actionMap: Record<string, string> = {}
    if (postPromptAction !== 'not-set') { activities.push('Post');     actionMap['Post']     = postPromptAction }
    if (uploadAction     !== 'not-set') { activities.push('Upload');   actionMap['Upload']   = uploadAction     }
    if (downloadAction   !== 'not-set') { activities.push('Download'); actionMap['Download'] = downloadAction   }
    if (activities.length === 0) activities.push('Upload', 'Post')

    exactMappings.push('post_prompt → activity Post')
    exactMappings.push('upload → activity Upload')
    exactMappings.push('download → activity Download')

    const actionsInUse = Object.values(actionMap).filter(a => a !== 'not-set')
    mostRestrictive = actionsInUse.includes('block')             ? 'block'
      : actionsInUse.some(a => a.startsWith('coach'))            ? 'coach'
      : actionsInUse.includes('alert')                           ? 'alert'
      : actionsInUse.includes('monitor')                         ? 'monitor'
      : 'allow'
  }

  // Destination = target + activities (matches Netskope UI layout)
  const destination = { ...destTarget, activities }

  let primaryNativeAction = toNetskopeAction(mostRestrictive)

  if (mostRestrictive === 'monitor') {
    lossyMappings.push('monitor mapped to Allow (Netskope has no Monitor action — policy will Allow traffic; add an alert profile if visibility is needed).')
  }

  // ── DLP profiles ──────────────────────────────────────────────────────────
  let dlpProfiles: string[] = []

  if (npj && npj.content.conditions.length > 0) {
    // npj-first: build profiles from typed conditions
    const dtSensitivities = new Set<string>()
    let hasLabelCondition = false
    let hasFilenameCondition = false

    for (const cond of npj.content.conditions) {
      if (cond.type === 'data_type') {
        dtSensitivities.add(cond.sensitivity)
      } else if (cond.type === 'classification_label') {
        hasLabelCondition = true
        // Classification labels map to a tenant-specific enterprise profile
        dlpProfiles.push(`EFFATA-LABEL-${cond.label_id.toUpperCase().replace(/[^A-Z0-9]/g, '-')}`)
        testsRequired.push(
          `Configure enterprise classification profile in Netskope matching label "${cond.label_name}" ` +
          `(source: ${cond.label_source}, key: ${cond.metadata_key}=${cond.metadata_value}).`,
        )
      } else if (cond.type === 'filename') {
        hasFilenameCondition = true
        unverifiedAreas.push('Filename pattern conditions — Netskope filename-based DLP detection is a separate product capability; verify tenant support.')
      }
    }

    for (const sensitivity of dtSensitivities) {
      dlpProfiles.push(dlpProfileName(sensitivity))
    }

    if (dtSensitivities.size > 0) {
      for (const sensitivity of dtSensitivities) {
        exactMappings.push(`npj.content.conditions[type=data_type, sensitivity=${sensitivity}] → DLP profile: ${dlpProfileName(sensitivity)}`)
        testsRequired.push(`Create or verify DLP profile "${dlpProfileName(sensitivity)}" exists in Netskope (Policies → DLP Profiles).`)
      }
    }
    if (hasLabelCondition) {
      lossyMappings.push('Classification label conditions require tenant-specific enterprise-classification profile in Netskope — cannot be auto-created.')
      unverifiedAreas.push('Public-doc parity for enterprise classification label conditions in Netskope.')
    }
    if (hasFilenameCondition) {
      lossyMappings.push('Filename detection conditions — Netskope filename-based DLP is a separate capability; verify tenant support before enabling.')
    }
  } else if (!npj) {
    // Legacy fallback
    const { profiles: legacyProfiles, source: profileSource } = inferDlpProfiles(policy)
    dlpProfiles = legacyProfiles

    if (profileSource === 'label') {
      exactMappings.push(`data_classification_label → DLP profile: ${dlpProfiles[0]} (must exist in Netskope tenant)`)
      testsRequired.push(
        `Create or verify DLP profile "${dlpProfiles[0]}" exists in Netskope (Policies → DLP Profiles) and matches the data patterns for "${policy.data_classification_label}".`,
      )
    } else if (profileSource === 'rules') {
      for (const p of dlpProfiles) {
        testsRequired.push(
          `Create or verify DLP profile "${p}" exists in Netskope (Policies → DLP Profiles) covering the relevant data patterns from this policy's rules.`,
        )
      }
      lossyMappings.push(
        `DLP profiles inferred from rule data_types (${dlpProfiles.join(', ')}) — no data_classification_label set. ` +
        `Verify these profile names match your Netskope tenant configuration.`,
      )
    } else {
      lossyMappings.push('No DLP profile configured — this policy acts on ALL content for the specified activities. Add a DLP profile in Netskope if content inspection is required.')
    }

    if (policy.rules.some(r => r.data_type.startsWith('clabel:'))) {
      lossyMappings.push('Sensitivity label conditions (clabel:) require tenant-specific enterprise-classification profile in Netskope — cannot be auto-created.')
      unverifiedAreas.push('Public-doc parity for generic label-condition syntax in Netskope.')
    }
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

  // Prohibited intent / govern_app_access always maps to Block
  const isProhibited = npj
    ? npj.intent === 'govern_app_access'
    : policy.policy_type === 'prohibited'
  if (isProhibited) {
    primaryNativeAction = 'Block'
    exactMappings.push(npj ? 'npj.intent govern_app_access → action Block' : 'policy_type prohibited → action Block')
    lossyMappings.push(
      'govern_app_access (browse + login) maps to Netskope Browse activity — blocks all URL-level access to the app. ' +
      'No DLP profile is needed; the Block action applies to all traffic matching the destination.',
    )
  }

  // Profile & Action
  const profileAction = dlpProfiles.length > 0
    ? { dlp_profiles: dlpProfiles, action: primaryNativeAction, notification_template: notificationTemplate }
    : null

  testsRequired.push(
    'Optionally configure a Traffic Action in Netskope (+ ADD TRAFFIC ACTION) if you want to Alert or Block ' +
    'on traffic that does not match any of the configured DLP profiles. Leave unset if downstream policies cover this.',
  )

  // ── Approved-use / exceptions → Allow policy ──────────────────────────────
  const shouldEmitAllow = npj
    ? npj.intent === 'allow_approved_use' || npj.exceptions.some(e => e.effect === 'allow')
    : (policy.policy_type === 'approved-use' || policy.primary_action === 'allow')

  if (shouldEmitAllow) {
    const allowActivities = npj
      ? activities   // already correctly set from npj.scope.activities
      : (() => {
          const arr: string[] = []
          const ua = resolveAction(policy, 'upload')
          const pa = resolveAction(policy, 'post_prompt')
          const da = resolveAction(policy, 'download')
          if (ua === 'allow') arr.push('Upload')
          if (pa === 'allow') arr.push('Post')
          if (da === 'allow') arr.push('Download')
          return arr.length === 0 ? ['Upload', 'Post'] : arr
        })()

    nativePolicies.push({
      name:           `[Allow] ${policy.name}`,
      description:    generateDescription('Allow', allowActivities, null, destTarget),
      status:         'enabled',
      source,
      destination:    { ...destTarget, activities: allowActivities },
      profile_action: null,
      action:         'Allow',
      group:          '1. Header Policies',
      policy_type:    'Cloud App Access',
      policy_family:  'Real-time Protection',
    })
    exactMappings.push(npj ? 'npj.intent allow_approved_use → Allow action' : 'approved-use → Allow action')
    testsRequired.push(
      'Validate Allow rule is scoped to an approved app instance + approved user group to avoid bypassing downstream DLP controls.',
      'Verify policy order in Netskope console — this Allow rule must sit above block/DLP rules for the same destination.',
    )
  }

  const descLabel = npj
    ? (npj.content.conditions.find(c => c.type === 'data_type') as { sensitivity?: string } | undefined)?.sensitivity ?? null
    : policy.data_classification_label ?? (dlpProfiles.length > 0 ? dlpProfiles[0].replace('EFFATA-', '').toLowerCase() : null)

  nativePolicies.push({
    name:           `[DLP] ${policy.name}`,
    description:    generateDescription(primaryNativeAction, activities, descLabel, destTarget),
    status:         'enabled',
    source,
    destination,
    profile_action: profileAction,
    action:         primaryNativeAction,
    group:          policyGroup(primaryNativeAction),
    policy_type:    'Cloud App Access',
    policy_family:  'Real-time Protection',
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
