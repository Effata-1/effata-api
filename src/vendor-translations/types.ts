export type MappingQuality = 'exact' | 'lossy' | 'split_required' | 'unsupported' | 'unverified'

export interface MappingReport {
  exact_mappings:            string[]
  lossy_mappings:            string[]
  unsupported_intent:        string[]
  unverified_vendor_areas:   string[]
  tests_required:            string[]
  customer_mapping_required: string[]  // missing tenant mappings that block exact translation
}

export interface TranslationResult {
  vendor:                   string
  /** success = fully mapped; partial = translated but lossy/unverified; deferred = vendor not supported */
  status:                   'success' | 'partial' | 'deferred'
  /** Vendor catalog version used at translation time. Empty string for non-catalog vendors. */
  catalog_version:          string
  /** Hash of org mappings used at translation time — empty string if no mappings loaded. */
  customer_mapping_version: string
  native_policies:          object[]
  mapping_report:           MappingReport
}

export interface OrgVendorObjectMapping {
  id:                          string
  org_id:                      string
  vendor_id:                   string
  neutral_object_type:         string
  neutral_object_key:          string
  neutral_object_display_name: string | null
  vendor_object_type:          string
  vendor_object_key:           string | null
  vendor_object_name:          string
  vendor_object_id:            string | null
  vendor_console_path:         string | null
  mapping_purpose:             'destination_scope' | 'detection_profile' | 'notification' | 'exception' | 'evidence' | 'policy_order'
  mapping_quality:             'exact' | 'lossy' | 'customer_verified' | 'customer_mapping_required' | 'not_applicable' | 'unverified'
  verification_status:         'unverified' | 'verified' | 'needs_review' | 'stale' | 'invalid'
  is_active:                   boolean
  not_applicable:              boolean
  not_applicable_reason:       string | null
  verified:                    boolean
  verified_by:                 string | null
  verified_at:                 string | null
  verification_note:           string | null
  updated_at:                  string
  metadata:                    Record<string, unknown>
}

export interface PolicyRule {
  data_type:   string
  post_prompt: string
  upload:      string
  download:    string
  response:    string
}

import type { NeutralPolicyV1 } from '../neutral-policies/types'

export type { NeutralPolicyV1 }

export interface NeutralPolicy {
  id:                        string
  name:                      string
  description:               string | null
  policy_type:               string
  policy_family:             string | null
  primary_action:            string | null
  data_classification_label: string | null
  scope_all_apps:            boolean
  scope_app_ids:             string[]
  rules:                     PolicyRule[]
  // Structured neutral policy JSON — populated by the compiler. Adapters should
  // use this as primary source; fall back to legacy fields only when null/invalid.
  neutral_policy_json?:      NeutralPolicyV1 | null
}

export interface VendorCapabilityRegistry {
  vendor_id: string
  version:   string
  features:  Record<string, string | boolean>
}

/** Action rank for "most restrictive wins" resolution across rules */
export const ACTION_RANK: Record<string, number> = {
  'not-set':    0,
  'allow':      1,
  'monitor':    2,
  'alert':      3,
  'coach':      4,
  'coach-ack':  4,
  'coach-just': 4,
  'block':      5,
}

/**
 * Resolve the effective action for a given activity across all rules.
 * Priority: rule-level activity action > primary_action > 'not-set'
 */
export function resolveAction(
  policy: NeutralPolicy,
  activity: keyof PolicyRule,
): string {
  let best = 'not-set'
  for (const rule of policy.rules) {
    const action = rule[activity] as string
    if ((ACTION_RANK[action] ?? 0) > (ACTION_RANK[best] ?? 0)) {
      best = action
    }
  }
  // Fall back to primary_action if no rule-level action is set
  if (best === 'not-set' && policy.primary_action) {
    return policy.primary_action
  }
  return best
}

/** Map Effata action codes to a severity label used by Forcepoint/Skyhigh */
export function actionToSeverity(action: string): string {
  switch (action) {
    case 'block':                  return 'Critical'
    case 'coach':
    case 'coach-ack':
    case 'coach-just':
    case 'alert':                  return 'High'
    case 'monitor':                return 'Medium'
    case 'allow':                  return 'Low'
    default:                       return 'Medium'
  }
}
