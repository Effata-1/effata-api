import { serviceClient } from '../lib/supabase'
import type { VendorCapabilityRegistry } from './types'

/**
 * Maps onboarding_profiles.tools values → vendor_capability_registries.vendor_id
 * Onboarding stores human-readable names; adapters use kebab-case IDs.
 */
const TOOL_NAME_TO_VENDOR_ID: Record<string, string> = {
  'netskope':           'netskope',
  'microsoft-purview':  'microsoft-purview',
  'microsoft purview':  'microsoft-purview',
  'microsoftpurview':   'microsoft-purview',
  'purview':            'microsoft-purview',
  'forcepoint-dlp':     'forcepoint-dlp',
  'forcepoint dlp':     'forcepoint-dlp',
  'forcepoint':         'forcepoint-dlp',
  'skyhigh-security':   'skyhigh-security',
  'skyhigh security':   'skyhigh-security',
  'skyhigh':            'skyhigh-security',
}

export const FIRST_WAVE_VENDOR_IDS = [
  'netskope',
  'microsoft-purview',
  'forcepoint-dlp',
  'skyhigh-security',
] as const

export type FirstWaveVendorId = (typeof FIRST_WAVE_VENDOR_IDS)[number]

/** Convert a tool name from onboarding_profiles to a canonical vendor_id, or null if not supported. */
export function normalizeVendorTool(toolName: string): string | null {
  return TOOL_NAME_TO_VENDOR_ID[toolName.toLowerCase().trim()] ?? null
}

/** Load active capability registries for a given set of vendor IDs. */
export async function loadRegistries(
  vendorIds: string[],
): Promise<Map<string, VendorCapabilityRegistry>> {
  if (vendorIds.length === 0) return new Map()

  const { data, error } = await serviceClient
    .from('vendor_capability_registries')
    .select('vendor_id, version, features')
    .in('vendor_id', vendorIds)
    .eq('is_active', true)

  if (error) throw new Error(`Failed to load capability registries: ${error.message}`)

  const map = new Map<string, VendorCapabilityRegistry>()
  for (const row of data ?? []) {
    map.set(row.vendor_id, {
      vendor_id: row.vendor_id,
      version:   row.version,
      features:  row.features as Record<string, string | boolean>,
    })
  }
  return map
}
