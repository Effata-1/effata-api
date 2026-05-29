import type { SupabaseClient } from '@supabase/supabase-js'
import { compileNeutralPoliciesForOrg } from './compiler'
import type { CompilerInput } from './compiler'
import { computeNeutralPolicyHash } from './hash'
import { COMPILER_VERSION } from './compiler'

export interface BackfillResult {
  orgId:    string
  compiled: number
  skipped:  number
  errors:   string[]
}

export async function backfillNeutralPolicies(
  orgId: string,
  client: SupabaseClient,
): Promise<BackfillResult> {
  const errors: string[] = []

  // Fetch all governance inputs in parallel
  const [
    catsResult, overridesResult, labelsResult,
    customerLabelsResult, dataTypesResult, profileResult,
  ] = await Promise.all([
    client
      .from('org_genai_governance_categories')
      .select('id, system_tag, name, active')
      .eq('org_id', orgId),

    client
      .from('org_control_matrix_overrides')
      .select('data_type, category_id, action_code')
      .eq('org_id', orgId),

    client
      .from('org_classification_labels')
      .select('id, system_level, name, active')
      .eq('org_id', orgId),

    client
      .from('org_customer_sensitivity_labels')
      .select('id, display_name, label_key, label_value, label_source, system_level, active')
      .eq('org_id', orgId),

    client
      .from('org_data_types')
      .select('slug, name, system_level')
      .eq('org_id', orgId)
      .eq('is_in_scope', true),

    client
      .from('onboarding_profiles')
      .select('tools, channels, rollout_mode')
      .eq('org_id', orgId)
      .maybeSingle(),
  ])

  if (!catsResult.data || !labelsResult.data || !dataTypesResult.data) {
    return { orgId, compiled: 0, skipped: 0, errors: ['Failed to fetch governance data'] }
  }

  const input: CompilerInput = {
    orgId,
    governanceCategories:      catsResult.data,
    controlMatrixOverrides:    overridesResult.data ?? [],
    classificationLabels:      labelsResult.data,
    customerSensitivityLabels: customerLabelsResult.data ?? [],
    inScopeDataTypes:          dataTypesResult.data,
    onboardingProfile:         {
      tools:        profileResult.data?.tools        ?? [],
      channels:     profileResult.data?.channels     ?? undefined,
      rollout_mode: profileResult.data?.rollout_mode ?? undefined,
    },
  }

  const compiled = compileNeutralPoliciesForOrg(input)
  if (compiled.length === 0) {
    return { orgId, compiled: 0, skipped: 0, errors: ['Compiler produced no outputs — check governance configuration'] }
  }

  let compiledCount = 0
  let skippedCount  = 0

  for (const output of compiled) {
    const { neutralPolicy, hash, legacyFields } = output
    const policyKey = neutralPolicy.policy_key

    // Check whether a policy with this key already has neutral_policy_json populated
    const { data: existing } = await client
      .from('org_genai_policies')
      .select('id, neutral_policy_json')
      .eq('org_id', orgId)
      .eq('policy_key', policyKey)
      .maybeSingle()

    if (existing && existing.neutral_policy_json && Object.keys(existing.neutral_policy_json).length > 0) {
      skippedCount++
      continue
    }

    const now = new Date().toISOString()
    const row = {
      org_id:                    orgId,
      policy_key:                policyKey,
      neutral_policy_json:       { ...neutralPolicy, provenance: { ...neutralPolicy.provenance, generated_from: 'legacy-backfill' as const, generated_at: now } },
      neutral_policy_version:    '1.0',
      neutral_policy_hash:       hash,
      name:                      legacyFields.name,
      description:               legacyFields.description,
      policy_type:               legacyFields.policy_type,
      policy_family:             legacyFields.policy_family,
      primary_action:            legacyFields.primary_action,
      data_classification_label: legacyFields.data_classification_label,
      scope_all_apps:            legacyFields.scope_all_apps,
      scope_app_ids:             legacyFields.scope_app_ids,
      rules:                     legacyFields.rules,
      generated_from:            'legacy-backfill',
      updated_at:                now,
    }

    const { error } = await client
      .from('org_genai_policies')
      .upsert(row, { onConflict: 'org_id,policy_key', ignoreDuplicates: false })

    if (error) {
      errors.push(`${policyKey}: ${error.message}`)
    } else {
      compiledCount++
    }
  }

  return { orgId, compiled: compiledCount, skipped: skippedCount, errors }
}

export { computeNeutralPolicyHash, COMPILER_VERSION }
