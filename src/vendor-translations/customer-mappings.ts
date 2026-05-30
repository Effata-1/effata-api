import crypto from 'crypto'
import { serviceClient } from '../lib/supabase'
import type { OrgVendorObjectMapping } from './types'

export async function getOrgVendorMappings(
  orgId: string,
  vendorId: string,
): Promise<OrgVendorObjectMapping[]> {
  const { data, error } = await serviceClient
    .from('org_vendor_object_mappings')
    .select('*')
    .eq('org_id', orgId)
    .eq('vendor_id', vendorId)
    .eq('is_active', true)

  if (error) throw new Error(`Failed to load vendor mappings: ${error.message}`)
  return (data ?? []) as OrgVendorObjectMapping[]
}

/**
 * Stable hash of the mappings array for stale detection.
 * Hashes semantically relevant fields so any meaningful change bumps the version.
 * The updated_at trigger on org_vendor_object_mappings guarantees updated_at changes on every write.
 */
export function computeMappingVersion(mappings: OrgVendorObjectMapping[]): string {
  const stable = JSON.stringify(
    mappings
      .map(m => ({
        id:                  m.id,
        neutral_object_type: m.neutral_object_type,
        neutral_object_key:  m.neutral_object_key,
        vendor_object_type:  m.vendor_object_type,
        vendor_object_name:  m.vendor_object_name,
        vendor_object_id:    m.vendor_object_id,
        mapping_quality:     m.mapping_quality,
        verification_status: m.verification_status,
        verified:            m.verified,
        not_applicable:      m.not_applicable,
        updated_at:          m.updated_at,
      }))
      .sort((a, b) => a.id.localeCompare(b.id)),
  )
  return crypto.createHash('sha256').update(stable).digest('hex').slice(0, 16)
}

export interface MappingLookupResult {
  found:          boolean
  mapping?:       OrgVendorObjectMapping
  /** Resolved quality signal for the mapping report. */
  quality:        'exact' | 'lossy' | 'customer_mapping_required' | 'unverified' | 'not_applicable'
  warning?:       string
  not_applicable: boolean
}

/**
 * Find the best matching mapping for a neutral object.
 * Does NOT throw on missing — returns quality = 'customer_mapping_required'.
 *
 * Quality resolution precedence:
 *   not_applicable → skip (no gap reported)
 *   lossy (any verified state) → always 'lossy' (intentional, not an error)
 *   missing / customer_mapping_required → 'customer_mapping_required'
 *   unverified or verified=false → 'unverified'
 *   verified + verification_status='verified' + quality='exact'|'customer_verified' → 'exact'
 */
export function findMapping(params: {
  mappings:            OrgVendorObjectMapping[]
  neutral_object_type: string
  neutral_object_key:  string
  vendor_object_type?: string
  mapping_purpose?:    OrgVendorObjectMapping['mapping_purpose']
}): MappingLookupResult {
  const { mappings, neutral_object_type, neutral_object_key, vendor_object_type, mapping_purpose } = params

  const match = mappings.find(m =>
    m.neutral_object_type === neutral_object_type &&
    m.neutral_object_key  === neutral_object_key &&
    (!vendor_object_type || m.vendor_object_type === vendor_object_type) &&
    (!mapping_purpose     || m.mapping_purpose    === mapping_purpose),
  )

  if (!match) {
    return {
      found:          false,
      quality:        'customer_mapping_required',
      not_applicable: false,
      warning: `No mapping configured for ${neutral_object_type}: ${neutral_object_key}. Add mapping in Vendor Mapping settings.`,
    }
  }

  if (match.not_applicable) {
    return { found: true, mapping: match, quality: 'not_applicable', not_applicable: true }
  }

  let quality: MappingLookupResult['quality']
  if (match.mapping_quality === 'lossy') {
    // Lossy is intentional — verified lossy stays lossy, not promoted to exact
    quality = 'lossy'
  } else if (match.mapping_quality === 'customer_mapping_required') {
    quality = 'customer_mapping_required'
  } else if (!match.verified || match.verification_status !== 'verified') {
    quality = 'unverified'
  } else if (match.mapping_quality === 'exact' || match.mapping_quality === 'customer_verified') {
    quality = 'exact'
  } else {
    quality = 'unverified'
  }

  return {
    found:          true,
    mapping:        match,
    quality,
    not_applicable: false,
    warning:
      quality === 'unverified'
        ? `Mapping for ${neutral_object_type}: ${neutral_object_key} → "${match.vendor_object_name}" is not yet verified in Netskope.`
        : quality === 'lossy'
          ? `Mapping for ${neutral_object_type}: ${neutral_object_key} → "${match.vendor_object_name}" is lossy.${match.verification_note ? ` Note: ${match.verification_note}` : ''}`
          : undefined,
  }
}
