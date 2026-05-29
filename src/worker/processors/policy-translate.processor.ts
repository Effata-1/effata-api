import { serviceClient } from '../../lib/supabase'
import { normalizeVendorTool, loadRegistries, FIRST_WAVE_VENDOR_IDS } from '../../vendor-translations/registry'
import { translateForVendor, adapterStatusToDbStatus } from '../../vendor-translations/translate'
import type { NeutralPolicy } from '../../vendor-translations/types'
import type { ProcessorContext } from '../job-config'

export async function policyTranslateProcessor(
  ctx: ProcessorContext,
): Promise<Record<string, unknown>> {
  const { orgId, payload } = ctx

  // Optional: translate only specific policies (from "Re-translate" single-policy action)
  const policyIds = Array.isArray(payload.policy_ids)
    ? (payload.policy_ids as string[])
    : null

  // Step 1: Parallel fetch — org tools + policies + (capability registries loaded after vendor filter)
  const [profileResult, policiesResult] = await Promise.all([
    serviceClient
      .from('onboarding_profiles')
      .select('tools')
      .eq('org_id', orgId)
      .maybeSingle(),
    (policyIds
      ? serviceClient
          .from('org_genai_policies')
          .select('id, name, description, policy_type, policy_family, primary_action, data_classification_label, scope_all_apps, scope_app_ids, rules')
          .eq('org_id', orgId)
          .in('id', policyIds)
      : serviceClient
          .from('org_genai_policies')
          .select('id, name, description, policy_type, policy_family, primary_action, data_classification_label, scope_all_apps, scope_app_ids, rules')
          .eq('org_id', orgId)
          .eq('is_active', true)
    ),
  ])

  const rawTools: string[] = (profileResult.data?.tools as string[] | null) ?? []
  const policies = (policiesResult.data ?? []) as NeutralPolicy[]

  if (policies.length === 0) {
    return { translated: 0, partial: 0, deferred: 0, errors: 0, message: 'No active policies found.' }
  }

  // Step 2: Normalize tool names → vendor IDs, filter to first-wave support
  const vendorIds = [...new Set(
    rawTools
      .map(t => normalizeVendorTool(t))
      .filter((id): id is string => id !== null && FIRST_WAVE_VENDOR_IDS.includes(id as (typeof FIRST_WAVE_VENDOR_IDS)[number]))
  )]

  if (vendorIds.length === 0) {
    return {
      translated: 0, partial: 0, deferred: 0, errors: 0,
      message: 'No first-wave vendor tools configured in onboarding profile.',
    }
  }

  // Step 3: Load capability registries for relevant vendors
  const registries = await loadRegistries(vendorIds)

  const total = policies.length * vendorIds.length
  let processed = 0
  let countTranslated = 0
  let countPartial    = 0
  let countDeferred   = 0
  let countErrors     = 0

  // Step 4: For each policy × vendor — translate + upsert
  for (const policy of policies) {
    for (const vendorId of vendorIds) {
      const registry = registries.get(vendorId)
      if (!registry) {
        countErrors++
        processed++
        continue
      }

      try {
        const { result, adapterVersion, registryVersion, policyHash } =
          translateForVendor(policy, vendorId, registry)

        const dbStatus = adapterStatusToDbStatus(result.status)

        const { error } = await serviceClient
          .from('org_vendor_translations')
          .upsert(
            {
              org_id:                      orgId,
              policy_id:                   policy.id,
              vendor_id:                   vendorId,
              status:                      dbStatus,
              adapter_version:             adapterVersion,
              capability_registry_version: registryVersion,
              neutral_policy_hash:         policyHash,
              native_policies:             result.native_policies,
              mapping_report:              result.mapping_report,
              // Reset review state on re-translation — previous review was for previous output
              reviewed_by:   null,
              reviewed_at:   null,
              exported_at:   null,
              updated_at:    new Date().toISOString(),
            },
            { onConflict: 'org_id,policy_id,vendor_id' },
          )

        if (error) {
          console.error(`[policy-translate] upsert error policy=${policy.id} vendor=${vendorId}:`, error.message)
          countErrors++
        } else {
          if (dbStatus === 'translated')  countTranslated++
          else if (dbStatus === 'partial') countPartial++
          else if (dbStatus === 'deferred') countDeferred++
        }
      } catch (err) {
        console.error(`[policy-translate] adapter error policy=${policy.id} vendor=${vendorId}:`, err)
        countErrors++
      }

      processed++
      await ctx.setProgress(total, processed)
    }
  }

  // Step 5: Update policy-level vendor_translation_status as aggregate summary
  // org_vendor_translations is the source of truth; this is a convenience summary
  await updatePolicyAggregate(orgId, policies.map(p => p.id))

  return {
    translated: countTranslated,
    partial:    countPartial,
    deferred:   countDeferred,
    errors:     countErrors,
    policies:   policies.length,
    vendors:    vendorIds.length,
  }
}

async function updatePolicyAggregate(orgId: string, policyIds: string[]): Promise<void> {
  for (const policyId of policyIds) {
    const { data: rows } = await serviceClient
      .from('org_vendor_translations')
      .select('status')
      .eq('org_id', orgId)
      .eq('policy_id', policyId)

    if (!rows || rows.length === 0) continue

    const statuses = rows.map(r => r.status as string)
    let aggregate: string

    if (statuses.every(s => s === 'verified')) {
      aggregate = 'verified'
    } else if (statuses.every(s => s === 'translated' || s === 'verified')) {
      aggregate = 'translated'
    } else if (statuses.some(s => s === 'partial' || s === 'error' || s === 'deferred')) {
      aggregate = 'partial'
    } else {
      aggregate = 'pending'
    }

    await serviceClient
      .from('org_genai_policies')
      .update({ vendor_translation_status: aggregate, updated_at: new Date().toISOString() })
      .eq('id', policyId)
      .eq('org_id', orgId)
  }
}
