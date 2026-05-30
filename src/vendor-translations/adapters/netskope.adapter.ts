import type { NeutralPolicy, TranslationResult, VendorCapabilityRegistry, OrgVendorObjectMapping } from '../types'
import { resolveAction } from '../types'
import { validateNeutralPolicy } from '../../neutral-policies/schema'
import { NETSKOPE_CATALOG, CATALOG_VERSION } from '../catalogs/netskope.catalog'
import { findMapping } from '../customer-mappings'

export const ADAPTER_VERSION = '4.0.0'

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

// ── Catalog helpers ───────────────────────────────────────────────────────────

/** Map Effata/NPJ action code → Netskope catalog action_key */
function toCatalogActionKey(effataAction: string): string {
  if (effataAction.startsWith('coach')) return 'user_alert'
  if (effataAction === 'block')   return 'block'
  if (effataAction === 'alert')   return 'alert'
  return 'allow'
}

/**
 * Enrich the mapping report arrays using the Netskope vendor catalog.
 * Called at the end of translate() once all local variables are settled.
 */
function applyCatalogEnrichment(params: {
  npjActivityKeys:  string[]
  activities:       string[]   // translated Netskope activity names (e.g. 'Browse', 'Upload')
  mostRestrictive:  string
  dlpProfileCount:  number
  scopeAllApps:     boolean
  scopeAppIds:      string[]
  intentTag:        string
  shouldEmitAllow:  boolean
  preserveEvidence: boolean
  hasLabelCondition: boolean
  lossyMappings:    string[]
  unsupportedIntent: string[]
  unverifiedAreas:  string[]
  testsRequired:    string[]
}): void {
  const {
    npjActivityKeys, activities, mostRestrictive, dlpProfileCount,
    scopeAllApps, scopeAppIds, intentTag, shouldEmitAllow, preserveEvidence,
    hasLabelCondition, lossyMappings, unsupportedIntent, unverifiedAreas, testsRequired,
  } = params

  const hasDlp      = dlpProfileCount > 0
  const actLower    = activities.map(a => a.toLowerCase())
  const execMode    = 'inline_real_time'

  // ── A. Activity warnings ──────────────────────────────────────────────────
  // formpost / prompt_submit → requires_dlp: true in catalog
  if (npjActivityKeys.includes('prompt_submit') || npjActivityKeys.includes('post')) {
    const entry = NETSKOPE_CATALOG.activities.find(a => a.activity_key === 'formpost')
    if (entry) {
      if (entry.requires_dlp === true && !hasDlp) {
        lossyMappings.push(
          'Formpost/prompt-submit activity requires a DLP profile in Netskope for GenAI prompt inspection — add a DLP profile to this policy.',
        )
      }
      if (entry.limitations.length > 0) unverifiedAreas.push(entry.limitations[0])
    }
  }

  // response activity → catalog says api_data_protection only (inline not universally verified)
  if (npjActivityKeys.includes('response')) {
    const entry = NETSKOPE_CATALOG.activities.find(a => a.activity_key === 'response')
    if (entry && !entry.execution_modes.includes(execMode)) {
      unsupportedIntent.push(
        `AI response inspection is not supported for inline Real-time Protection in Netskope. ` +
        (entry.limitations[0] ?? 'Validate per app and control plane.'),
      )
    }
  }

  // browse special event behavior — access control policies need this noted
  if (npjActivityKeys.includes('browse') || npjActivityKeys.includes('login')) {
    const entry = NETSKOPE_CATALOG.activities.find(a => a.activity_key === 'browse')
    if (entry && entry.event_emission_behavior === 'special_case' && entry.limitations.length > 0) {
      unverifiedAreas.push(entry.limitations[0])
    }
  }

  // ── B. Action constraints ─────────────────────────────────────────────────
  // quarantine: only valid for upload activity with a DLP profile
  if (mostRestrictive === 'quarantine' || intentTag === 'quarantine') {
    const entry = NETSKOPE_CATALOG.actions.find(a => a.action_key === 'quarantine')
    if (entry) {
      lossyMappings.push(...entry.limitations)
      if (!actLower.includes('upload')) {
        lossyMappings.push('Quarantine requires Upload activity — ensure the policy includes Upload in its activity selector.')
      }
    }
  }

  // encryption: requires app_instance + upload
  if (mostRestrictive === 'encryption' || intentTag === 'encryption') {
    const entry = NETSKOPE_CATALOG.actions.find(a => a.action_key === 'encryption')
    if (entry) lossyMappings.push(...entry.limitations)
  }

  // For the primary action, surface any action-level limitations not already covered
  const primaryCatalogAction = NETSKOPE_CATALOG.actions.find(a => a.action_key === toCatalogActionKey(mostRestrictive))
  if (primaryCatalogAction) {
    for (const lim of primaryCatalogAction.limitations) {
      if (!lossyMappings.includes(lim) && !unverifiedAreas.includes(lim)) {
        unverifiedAreas.push(lim)
      }
    }
  }

  // ── C. Cross-cutting limitation warnings (critical/high) ──────────────────
  const skipLimitations = new Set<string>([
    'api_inline_model_divergence',    // only relevant when mixing inline+API intentionally
    ...(npjActivityKeys.includes('response') ? [] : ['genai_response_not_universal_inline']),
    ...(scopeAllApps || scopeAppIds.length === 0 ? [] : ['generic_genai_category_mapping_lossy']),
  ])

  for (const lim of NETSKOPE_CATALOG.limitations) {
    if (lim.severity !== 'critical' && lim.severity !== 'high') continue
    if (skipLimitations.has(lim.limitation_key)) continue
    // ssl_dnd / certificate pinning — only surface when DLP inspection is expected
    if (['ssl_dnd_bypasses_inspection', 'certificate_pinned_apps'].includes(lim.limitation_key) && !hasDlp) continue
    const warning = `[${lim.severity.toUpperCase()}] ${lim.recommended_warning}`
    if (!unverifiedAreas.includes(warning) && !lossyMappings.includes(warning)) {
      unverifiedAreas.push(warning)
    }
  }

  // ── D. Prerequisite-driven test requirements ──────────────────────────────
  for (const prereq of NETSKOPE_CATALOG.prerequisites) {
    if (prereq.blocks_verification_if_missing !== true) continue
    if (!prereq.applies_to.some(t => [execMode, 'inline_real_time', 'dlp', 'destination_scope', 'vendor_translation'].includes(t))) continue
    // Skip DLP prereqs when no DLP profile is in the policy
    if (['dlp_profile_created', 'ssl_inspection_enabled'].includes(prereq.requirement_key) && !hasDlp) continue
    // Skip API connector prereq for inline policies
    if (prereq.requirement_key === 'api_connector_enabled') continue
    testsRequired.push(
      `[Prerequisite — ${prereq.severity.toUpperCase()}] ${prereq.title}: ${prereq.description} Validation: ${prereq.validation_method}`,
    )
  }

  // ── E. Structured catalog test requirements ───────────────────────────────
  const catalogTestMatches = NETSKOPE_CATALOG.test_requirements.filter(t => {
    const tags = t.applies_to
    if (tags.includes(intentTag)) return true
    if (t.test_key === 'inline_upload_dlp_positive_test' && actLower.includes('upload') && hasDlp) return true
    if (t.test_key === 'inline_post_formpost_dlp_positive_test' && (actLower.includes('post') || actLower.includes('formpost')) && hasDlp) return true
    if (t.test_key === 'policy_order_negative_test' && shouldEmitAllow) return true
    if (t.test_key === 'forensic_evidence_test' && preserveEvidence) return true
    if (t.test_key === 'label_detection_test' && hasLabelCondition) return true
    if (t.test_key === 'generic_genai_scope_negative_test' && (scopeAllApps || scopeAppIds.length === 0)) return true
    return false
  })

  for (const t of catalogTestMatches) {
    const evidence = t.evidence_to_capture.length > 0
      ? ` Evidence: ${t.evidence_to_capture.join(', ')}.`
      : ''
    testsRequired.push(
      `[Catalog ${t.severity.toUpperCase()}] ${t.title}: ${t.test_step} → ${t.expected_result}${evidence}`,
    )
  }
}

export function translate(
  policy:    NeutralPolicy,
  _registry: VendorCapabilityRegistry,
  mappings:  OrgVendorObjectMapping[] = [],
): TranslationResult {
  const exactMappings: string[]           = []
  const lossyMappings: string[]           = []
  const unsupportedIntent: string[]       = []
  const unverifiedAreas: string[]         = []
  const testsRequired: string[]           = []
  const customerMappingRequired: string[] = []
  const nativePolicies: object[]          = []
  // Hoisted for catalog enrichment — populated as the function progresses
  const npjActivityKeys: string[]         = []
  let   hasLabelCondition                 = false
  let   hasMissingDestMapping             = false

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

  // Destination category/apps — resolved below; placeholder until NPJ app_categories are processed
  let destTarget: Record<string, string | string[]> = { category: 'Generative AI' }

  // ── Activities and primary action ─────────────────────────────────────────
  const activities: string[] = []
  let mostRestrictive: string

  if (npj) {
    // Capture raw NPJ activity keys for catalog enrichment
    npjActivityKeys.push(...(npj.scope.activities ?? []))

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

    // Destination — use npj.scope.app_categories with customer mappings
    const appCategories = npj.scope.app_categories ?? []
    if (appCategories.length > 0) {
      const mappedNames: string[] = []
      for (const cat of appCategories) {
        const key = cat.system_tag ?? cat.id
        const lookup = findMapping({ mappings, neutral_object_type: 'app_category', neutral_object_key: key })
        if (lookup.not_applicable) continue
        if (lookup.found && lookup.mapping) {
          mappedNames.push(lookup.mapping.vendor_object_name)
          if (lookup.quality === 'exact') {
            exactMappings.push(`app_category [${key}] → "${lookup.mapping.vendor_object_name}" (verified)`)
          } else if (lookup.quality === 'lossy') {
            lossyMappings.push(lookup.warning!)
          } else {
            unverifiedAreas.push(lookup.warning!)
          }
        } else {
          hasMissingDestMapping = true
          customerMappingRequired.push(lookup.warning!)
          // Placeholder — do NOT silently substitute "Generative AI" for a specific category
          mappedNames.push(`[PLACEHOLDER: map ${key} in Vendor Mapping]`)
        }
      }
      destTarget = mappedNames.length === 1
        ? { category: mappedNames[0] }
        : { categories: mappedNames }
    } else if (policy.scope_all_apps) {
      destTarget = { category: 'Generative AI' }
      exactMappings.push('scope_all_apps → destination category: Generative AI')
    } else if (policy.scope_app_ids.length > 0) {
      destTarget = { specific_apps: policy.scope_app_ids }
      exactMappings.push('scope_app_ids → destination specific_apps')
    } else {
      destTarget = { category: 'Generative AI' }
      lossyMappings.push('No app categories or specific apps scoped — destination defaulted to Generative AI category.')
    }
  } else {
    // Legacy path — destination + activities from rules/primary_action
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
    const dtSensitivities    = new Set<string>()
    let   hasFilenameCondition = false

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

    // Use customer mappings for sensitivity → DLP profile
    for (const sensitivity of dtSensitivities) {
      const lookup = findMapping({ mappings, neutral_object_type: 'sensitivity_level', neutral_object_key: sensitivity })
      if (lookup.not_applicable) {
        // Intentionally skipped
      } else if (lookup.found && lookup.mapping) {
        dlpProfiles.push(lookup.mapping.vendor_object_name)
        if (lookup.quality === 'exact') {
          exactMappings.push(`npj.content.conditions[sensitivity=${sensitivity}] → DLP profile: "${lookup.mapping.vendor_object_name}" (verified)`)
        } else if (lookup.quality === 'lossy') {
          lossyMappings.push(lookup.warning!)
          testsRequired.push(`Verify DLP profile "${lookup.mapping.vendor_object_name}" covers "${sensitivity}" data patterns in Netskope.`)
        } else {
          unverifiedAreas.push(lookup.warning!)
          testsRequired.push(`Verify DLP profile "${lookup.mapping.vendor_object_name}" exists in Netskope (Policies → DLP Profiles).`)
        }
      } else {
        customerMappingRequired.push(lookup.warning!)
        dlpProfiles.push(dlpProfileName(sensitivity))  // placeholder only
        lossyMappings.push(`Using placeholder DLP profile name "${dlpProfileName(sensitivity)}" for "${sensitivity}" — configure exact profile name in Vendor Mapping.`)
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
    // Legacy fallback — try customer mappings for sensitivity levels, then fall back to inferred names
    const { profiles: legacyProfiles, source: profileSource } = inferDlpProfiles(policy)

    if (profileSource === 'label' && policy.data_classification_label && policy.data_classification_label !== 'all') {
      const sensitivity = policy.data_classification_label
      const lookup = findMapping({ mappings, neutral_object_type: 'sensitivity_level', neutral_object_key: sensitivity })
      if (lookup.not_applicable) {
        // skip
      } else if (lookup.found && lookup.mapping) {
        dlpProfiles.push(lookup.mapping.vendor_object_name)
        if (lookup.quality === 'exact') {
          exactMappings.push(`data_classification_label → DLP profile: "${lookup.mapping.vendor_object_name}" (verified)`)
        } else {
          unverifiedAreas.push(lookup.warning!)
          testsRequired.push(`Verify DLP profile "${lookup.mapping.vendor_object_name}" exists in Netskope.`)
        }
      } else {
        customerMappingRequired.push(lookup.warning!)
        dlpProfiles = legacyProfiles
        lossyMappings.push(`Using placeholder DLP profile name "${legacyProfiles[0]}" — configure exact profile name in Vendor Mapping.`)
        testsRequired.push(`Create or verify DLP profile "${legacyProfiles[0]}" exists in Netskope (Policies → DLP Profiles).`)
      }
    } else if (profileSource === 'rules') {
      // For rule-based profiles, keep legacy names and note as placeholders
      dlpProfiles = legacyProfiles
      for (const p of dlpProfiles) {
        testsRequired.push(`Create or verify DLP profile "${p}" exists in Netskope (Policies → DLP Profiles).`)
      }
      lossyMappings.push(
        `DLP profiles inferred from rule data_types (${dlpProfiles.join(', ')}) — no data_classification_label set. ` +
        `Verify these profile names match your Netskope tenant or configure exact names in Vendor Mapping.`,
      )
    } else {
      dlpProfiles = legacyProfiles
      if (dlpProfiles.length === 0) {
        lossyMappings.push('No DLP profile configured — this policy acts on ALL content for the specified activities. Add a DLP profile in Netskope if content inspection is required.')
      }
    }

    if (policy.rules.some(r => r.data_type.startsWith('clabel:'))) {
      lossyMappings.push('Sensitivity label conditions (clabel:) require tenant-specific enterprise-classification profile in Netskope — cannot be auto-created.')
      unverifiedAreas.push('Public-doc parity for generic label-condition syntax in Netskope.')
    }
  }

  // Notification template for coach — use customer mapping
  let notificationTemplate: string | null = null
  if (mostRestrictive.startsWith('coach')) {
    const tplLookup = findMapping({ mappings, neutral_object_type: 'notification_template', neutral_object_key: 'default-coach' })
    if (tplLookup.not_applicable) {
      // coaching notification explicitly disabled — no template
    } else if (tplLookup.found && tplLookup.mapping) {
      notificationTemplate = tplLookup.mapping.vendor_object_name
      if (tplLookup.quality === 'exact') {
        exactMappings.push(`coach → notification_template: "${notificationTemplate}" (verified)`)
      } else {
        unverifiedAreas.push(tplLookup.warning!)
        testsRequired.push(`Verify user notification template "${notificationTemplate}" exists in Netskope (Policies → User Notifications).`)
      }
    } else {
      customerMappingRequired.push(tplLookup.warning!)
      notificationTemplate = 'EFFATA-COACH-NOTIFICATION'  // placeholder
      testsRequired.push('Create or verify user notification template "EFFATA-COACH-NOTIFICATION" in Netskope (Policies → User Notifications).')
    }
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

  // Placeholder fields added when destination mapping is missing (policy is not deployment-ready)
  const placeholderFields = hasMissingDestMapping
    ? { _deployment_ready: false, _notes: 'Placeholder — configure Netskope app category mappings in Vendor Mapping before deploying.' }
    : {}

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
      ...placeholderFields,
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
    ...placeholderFields,
  })

  if (!hasMissingDestMapping) {
    testsRequired.push('Validate Netskope app category or destination covers all target AI apps in your tenant.')
  }

  // ── Catalog enrichment ────────────────────────────────────────────────────
  applyCatalogEnrichment({
    npjActivityKeys,
    activities,
    mostRestrictive,
    dlpProfileCount:   dlpProfiles.length,
    scopeAllApps:      policy.scope_all_apps,
    scopeAppIds:       policy.scope_app_ids,
    intentTag:         npj ? npj.intent : (policy.policy_type ?? 'unknown'),
    shouldEmitAllow,
    preserveEvidence:  npj?.decision.preserve_evidence ?? false,
    hasLabelCondition,
    lossyMappings,
    unsupportedIntent,
    unverifiedAreas,
    testsRequired,
  })

  // Status: block app_access with missing destination → deferred (not deployment-ready)
  const isBlockWithMissingDest = hasMissingDestMapping
    && (policy.policy_type === 'app_access' || npj?.intent === 'govern_app_access')
    && (primaryNativeAction === 'Block' || (npj?.decision.mode === 'block'))

  return {
    vendor:                   'netskope',
    catalog_version:          CATALOG_VERSION,
    customer_mapping_version: '',  // set by translateForVendor after passing mappings
    status: isBlockWithMissingDest          ? 'deferred'
      : customerMappingRequired.length > 0  ? 'partial'
      : lossyMappings.length > 0 || unsupportedIntent.length > 0 ? 'partial'
      : 'success',
    native_policies: nativePolicies,
    mapping_report: {
      exact_mappings:            exactMappings,
      lossy_mappings:            lossyMappings,
      unsupported_intent:        unsupportedIntent,
      unverified_vendor_areas:   unverifiedAreas,
      tests_required:            testsRequired,
      customer_mapping_required: customerMappingRequired,
    },
  }
}
