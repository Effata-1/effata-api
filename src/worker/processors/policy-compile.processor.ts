import { serviceClient } from '../../lib/supabase'
import { compileNeutralPoliciesForOrg } from '../../neutral-policies/compiler'
import type { CompilerInput } from '../../neutral-policies/compiler'
import type { ProcessorContext } from '../job-config'

export async function policyCompileProcessor(ctx: ProcessorContext): Promise<Record<string, unknown>> {
  const { orgId } = ctx

  await ctx.setProgress(5, 0)

  // Step 1 — Fetch all governance inputs in parallel
  const [
    catsResult, overridesResult, labelsResult,
    customerLabelsResult, orgDataTypesResult, catalogDataTypesResult, profileResult,
  ] = await Promise.all([
    serviceClient
      .from('org_genai_governance_categories')
      .select('id, system_tag, name, active')
      .eq('org_id', orgId),

    serviceClient
      .from('org_control_matrix_overrides')
      .select('data_type, category_id, action_code')
      .eq('org_id', orgId),

    serviceClient
      .from('org_classification_labels')
      .select('id, system_level, name, active')
      .eq('org_id', orgId),

    serviceClient
      .from('org_customer_sensitivity_labels')
      .select('id, display_name, label_key, label_value, label_source, system_level, active')
      .eq('org_id', orgId),

    // org_data_types has no slug/system_level — must join with catalog_data_types
    serviceClient
      .from('org_data_types')
      .select('id, name, catalog_data_type_id')
      .eq('org_id', orgId)
      .eq('is_in_scope', true),

    serviceClient
      .from('catalog_data_types')
      .select('id, slug, name, system_level')
      .eq('active', true),

    serviceClient
      .from('onboarding_profiles')
      .select('tools, channels, rollout_mode')
      .eq('org_id', orgId)
      .maybeSingle(),
  ])

  if (catsResult.error)            throw new Error(`Failed to fetch governance categories: ${catsResult.error.message}`)
  if (labelsResult.error)          throw new Error(`Failed to fetch classification labels: ${labelsResult.error.message}`)
  if (orgDataTypesResult.error)    throw new Error(`Failed to fetch data types: ${orgDataTypesResult.error.message}`)
  if (catalogDataTypesResult.error) throw new Error(`Failed to fetch catalog data types: ${catalogDataTypesResult.error.message}`)

  // Join org_data_types → catalog_data_types to resolve slug and system_level
  const catalogMap = new Map((catalogDataTypesResult.data ?? []).map(c => [c.id, c]))
  const inScopeDataTypes = (orgDataTypesResult.data ?? []).flatMap(dt => {
    if (!dt.catalog_data_type_id) return []
    const cat = catalogMap.get(dt.catalog_data_type_id)
    if (!cat) return []
    return [{ slug: cat.slug, name: dt.name, system_level: cat.system_level }]
  })

  await ctx.setProgress(5, 1)

  const input: CompilerInput = {
    orgId,
    governanceCategories:      catsResult.data ?? [],
    controlMatrixOverrides:    overridesResult.data ?? [],
    classificationLabels:      labelsResult.data ?? [],
    customerSensitivityLabels: customerLabelsResult.data ?? [],
    inScopeDataTypes,
    onboardingProfile: {
      tools:        profileResult.data?.tools        ?? [],
      channels:     profileResult.data?.channels     ?? undefined,
      rollout_mode: profileResult.data?.rollout_mode ?? undefined,
    },
  }

  // Step 2 — Run compiler
  const outputs = compileNeutralPoliciesForOrg(input)
  if (outputs.length === 0) {
    return { compiled: 0, updated: 0, skipped: 0, warnings: ['No policies compiled — check governance configuration'] }
  }

  await ctx.setProgress(5, 2)

  // Step 3 — Upsert each policy by (org_id, policy_key)
  let updated = 0
  let skipped = 0
  const now = new Date().toISOString()

  for (const output of outputs) {
    const { neutralPolicy, hash, legacyFields } = output
    const policyKey = neutralPolicy.policy_key

    // Check if an existing policy with this key is already up-to-date (same hash)
    const { data: existing } = await serviceClient
      .from('org_genai_policies')
      .select('id, neutral_policy_hash')
      .eq('org_id', orgId)
      .eq('policy_key', policyKey)
      .maybeSingle()

    if (existing?.neutral_policy_hash === hash) {
      skipped++
      continue
    }

    const row = {
      org_id:                    orgId,
      policy_key:                policyKey,
      neutral_policy_json:       neutralPolicy,
      neutral_policy_version:    '1.0',
      neutral_policy_hash:       hash,
      // Legacy fields — written for UI display and backward compat
      name:                      legacyFields.name,
      description:               legacyFields.description,
      policy_type:               legacyFields.policy_type,
      policy_family:             legacyFields.policy_family,
      primary_action:            legacyFields.primary_action,
      data_classification_label: legacyFields.data_classification_label,
      scope_all_apps:            legacyFields.scope_all_apps,
      scope_app_ids:             legacyFields.scope_app_ids,
      rules:                     legacyFields.rules,
      generated_from:            'governance-matrix',
      priority:                  legacyFields.priority,
      updated_at:                now,
    }

    const { error } = await serviceClient
      .from('org_genai_policies')
      .upsert(row, {
        onConflict:        'org_id,policy_key',
        ignoreDuplicates:  false,
      })

    if (error) throw new Error(`Failed to upsert policy "${policyKey}": ${error.message}`)
    updated++
  }

  await ctx.setProgress(5, 3)

  // Step 4 — Mark any previously compiler-managed policies that were not produced this run as inactive
  // (Only policies with generated_from = 'governance-matrix' and policy_key set)
  const compiledKeys = outputs.map(o => o.neutralPolicy.policy_key)
  if (compiledKeys.length > 0) {
    await serviceClient
      .from('org_genai_policies')
      .update({ is_active: false, updated_at: now })
      .eq('org_id', orgId)
      .eq('generated_from', 'governance-matrix')
      .not('policy_key', 'is', null)
      .not('policy_key', 'in', `(${compiledKeys.map(k => `"${k}"`).join(',')})`)
  }

  await ctx.setProgress(5, 5)

  return {
    compiled: outputs.length,
    updated,
    skipped,
  }
}
