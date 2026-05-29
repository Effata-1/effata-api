import crypto from 'crypto'
import type { NeutralPolicy, TranslationResult, VendorCapabilityRegistry } from './types'
import * as netskope  from './adapters/netskope.adapter'
import * as purview   from './adapters/purview.adapter'
import * as forcepoint from './adapters/forcepoint.adapter'
import * as skyhigh   from './adapters/skyhigh.adapter'

type AdapterModule = {
  ADAPTER_VERSION: string
  translate: (policy: NeutralPolicy, registry: VendorCapabilityRegistry) => TranslationResult
}

const ADAPTERS: Record<string, AdapterModule> = {
  'netskope':         netskope,
  'microsoft-purview': purview,
  'forcepoint-dlp':   forcepoint,
  'skyhigh-security': skyhigh,
}

/**
 * Compute a stable SHA-256 hash of the policy fields that affect translation output.
 * Used to detect when a policy has changed since last translation (staleness indicator).
 */
export function computePolicyHash(policy: NeutralPolicy): string {
  const stable = JSON.stringify({
    primary_action:            policy.primary_action,
    data_classification_label: policy.data_classification_label,
    scope_all_apps:            policy.scope_all_apps,
    scope_app_ids:             [...policy.scope_app_ids].sort(),
    policy_type:               policy.policy_type,
    rules:                     [...policy.rules].sort((a, b) => a.data_type.localeCompare(b.data_type)),
  })
  return crypto.createHash('sha256').update(stable).digest('hex').slice(0, 16)
}

/**
 * Run the adapter for a single vendor against a neutral policy.
 * Returns the TranslationResult plus metadata for storage.
 */
export function translateForVendor(
  policy: NeutralPolicy,
  vendorId: string,
  registry: VendorCapabilityRegistry,
): {
  result: TranslationResult
  adapterVersion: string
  registryVersion: string
  policyHash: string
} {
  const adapter = ADAPTERS[vendorId]
  if (!adapter) {
    return {
      result: {
        vendor:          vendorId,
        status:          'deferred',
        native_policies: [],
        mapping_report: {
          exact_mappings:          [],
          lossy_mappings:          [],
          unsupported_intent:      [],
          unverified_vendor_areas: [`No adapter available for vendor: ${vendorId}`],
          tests_required:          [],
        },
      },
      adapterVersion:  '0.0.0',
      registryVersion: registry.version,
      policyHash:      computePolicyHash(policy),
    }
  }

  const result = adapter.translate(policy, registry)

  return {
    result,
    adapterVersion:  adapter.ADAPTER_VERSION,
    registryVersion: registry.version,
    policyHash:      computePolicyHash(policy),
  }
}

/** Map adapter result status → DB status */
export function adapterStatusToDbStatus(
  adapterStatus: TranslationResult['status'],
): 'translated' | 'partial' | 'deferred' {
  switch (adapterStatus) {
    case 'success': return 'translated'
    case 'partial': return 'partial'
    case 'deferred': return 'deferred'
    default:        return 'partial'
  }
}
