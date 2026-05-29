import { serviceClient } from '../../lib/supabase'
import { logAiRun } from '../../lib/ai-log'
import { generatePolicyPack, type PolicyPackRecommendation } from '../../ai/agents/policy-pack'
import { buildNeutralPolicyFromPackOutput } from '../../neutral-policies/pack-builder'
import type { ProcessorContext } from '../job-config'

interface RejectedPolicy {
  name:   string
  reason: string
}

function validatePolicyDomainRules(policies: PolicyPackRecommendation[]): {
  valid:    PolicyPackRecommendation[]
  rejected: RejectedPolicy[]
} {
  const valid: PolicyPackRecommendation[]   = []
  const rejected: RejectedPolicy[] = []

  for (const p of policies) {
    if (p.policy_type === 'prohibited' && p.primary_action !== 'block') {
      rejected.push({ name: p.name, reason: 'prohibited policy must use block action' })
    } else if (p.policy_type === 'approved-use' && p.primary_action !== 'allow') {
      rejected.push({ name: p.name, reason: 'approved-use policy must use allow action' })
    } else {
      valid.push(p)
    }
  }

  return { valid, rejected }
}

export async function policyPackProcessor(ctx: ProcessorContext): Promise<Record<string, unknown>> {
  const { orgId, userId, jobId } = ctx
  const start = Date.now()

  await ctx.setProgress(4, 0)

  // Step 1 — Fetch all org data
  const [profileResult, reviewResult, classResult, existingResult, customerLabelsResult] = await Promise.all([
    serviceClient
      .from('onboarding_profiles')
      .select('industry, regions, tools, data_categories, top_priorities, policy_presence, policy_mode')
      .eq('org_id', orgId)
      .maybeSingle(),

    serviceClient
      .from('dlp_coverage_ai_reviews')
      .select('coverage_score, gaps')
      .eq('org_id', orgId)
      .order('reviewed_at', { ascending: false })
      .limit(1)
      .maybeSingle(),

    serviceClient
      .from('genai_customer_classifications')
      .select('customer_classification')
      .eq('org_id', orgId),

    serviceClient
      .from('org_genai_policies')
      .select('policy_family, priority')
      .eq('org_id', orgId),

    serviceClient
      .from('org_customer_sensitivity_labels')
      .select('display_name, system_level')
      .eq('org_id', orgId)
      .eq('active', true),
  ])

  const profile = profileResult.data
  if (!profile) throw new Error('No onboarding profile found')

  const review = reviewResult.data
  if (!review) throw new Error('No coverage review found — run a coverage review before generating a policy pack')

  const classRows      = classResult.data ?? []
  const existingRows   = existingResult.data ?? []
  const customerLabels = (customerLabelsResult.data ?? []) as Array<{ display_name: string; system_level: string | null }>

  const countByClass = (cls: string) =>
    classRows.filter((r: { customer_classification: string }) => r.customer_classification === cls).length

  const existingPolicyFamilies = [
    ...new Set(
      existingRows
        .map((r: { policy_family: string | null }) => r.policy_family)
        .filter((f): f is string => f != null && f.length > 0)
    ),
  ]

  const existingMaxPriority = existingRows.reduce(
    (max: number, r: { priority: number | null }) => Math.max(max, r.priority ?? 0),
    0,
  )

  await ctx.setProgress(4, 1)

  // Step 2 — Call AI
  const { result, inputTokens, outputTokens } = await generatePolicyPack({
    orgProfile: {
      industry:        profile.industry        ?? null,
      regions:         profile.regions         ?? [],
      tools:           profile.tools           ?? [],
      data_categories: profile.data_categories ?? [],
      top_priorities:  profile.top_priorities  ?? [],
      policy_presence: profile.policy_presence ?? null,
      policy_mode:     profile.policy_mode     ?? null,
    },
    coverageScore:  review.coverage_score ?? 0,
    coverageGaps:   Array.isArray(review.gaps) ? review.gaps as Array<{ channel: string; severity: string; description: string }> : [],
    appCounts: {
      enterprise_approved:      countByClass('enterprise-approved'),
      approved_with_conditions: countByClass('approved-with-conditions'),
      restricted:               countByClass('permitted-with-restriction'),
      prohibited:               countByClass('prohibited'),
    },
    existingPolicyFamilies,
    hasCustomerLabels:    customerLabels.length > 0,
    customerLabelSummary: customerLabels.map(l => `${l.display_name}${l.system_level ? ` (${l.system_level})` : ''}`),
  })

  await ctx.setProgress(4, 2)

  // Step 3 — Domain-rule validation
  const { valid, rejected } = validatePolicyDomainRules(result.policies)

  if (rejected.length > 0) {
    console.warn(`[policy-pack] ${rejected.length} policies rejected by domain rules:`, rejected)
  }

  if (valid.length === 0) {
    throw new Error('All AI-generated policies failed domain validation')
  }

  await ctx.setProgress(4, 3)

  // Step 4 — Insert policies
  const now = new Date().toISOString()
  const rows = valid.map((rec, i) => ({
    org_id:                    orgId,
    name:                      rec.name,
    description:               rec.description,
    policy_type:               rec.policy_type,
    policy_family:             rec.policy_family,
    data_classification_label: rec.data_classification_label,
    primary_action:            rec.primary_action,
    scope_all_apps:            rec.scope_all_apps,
    scope_app_ids:             [],
    rules:                     [],
    required_dependencies:     [],
    priority:                  existingMaxPriority + i + 1,
    notes:                     rec.rationale,
    generated_from:            'policy-pack-agent',
    source_job_id:             jobId,
    generation_context: {
      coverage_score_at_generation: review.coverage_score,
      generated_at:                 now,
    },
    approval_status:            'draft',
    is_active:                  false,
    vendor_translation_status:  'pending',
    test_status:                'untested',
    updated_at:                 now,
  }))

  const { data: insertedRows, error: insertError } = await serviceClient
    .from('org_genai_policies')
    .insert(rows)
    .select('id, name, description, policy_type, policy_family, primary_action, data_classification_label, scope_all_apps, scope_app_ids')
  if (insertError) throw new Error(`Failed to insert policies: ${insertError.message}`)

  // Fetch in-scope data types for the org (needed by pack-builder to build content conditions)
  const { data: inScopeDataTypes } = await serviceClient
    .from('org_data_types')
    .select('slug, name, system_level')
    .eq('org_id', orgId)
    .eq('is_in_scope', true)

  const context = { inScopeDataTypes: inScopeDataTypes ?? [] }

  // Build and persist neutral_policy_json for each inserted policy
  if (insertedRows && insertedRows.length > 0) {
    const neutralUpdates = insertedRows.map(row => {
      const aiPolicy = {
        id:                        row.id as string,
        name:                      row.name as string,
        description:               row.description as string,
        policy_type:               row.policy_type as 'usage' | 'data-handling' | 'approved-use' | 'prohibited',
        policy_family:             (row.policy_family ?? 'GenAI Content Detection') as string,
        primary_action:            (row.primary_action ?? 'monitor') as string,
        data_classification_label: (row.data_classification_label ?? 'all') as string,
        scope_all_apps:            row.scope_all_apps as boolean,
        scope_app_ids:             (row.scope_app_ids ?? []) as string[],
      }
      const { neutralPolicy, hash } = buildNeutralPolicyFromPackOutput(aiPolicy, context)
      return { id: row.id as string, neutralPolicy, hash }
    })

    for (const { id, neutralPolicy, hash } of neutralUpdates) {
      await serviceClient
        .from('org_genai_policies')
        .update({
          neutral_policy_json:    neutralPolicy,
          neutral_policy_version: '1.0',
          neutral_policy_hash:    hash,
          policy_key:             neutralPolicy.policy_key,
        })
        .eq('id', id)
        .eq('org_id', orgId)
    }
  }

  void logAiRun({
    orgId,
    userId,
    agent:        'policy-pack',
    runType:      'user',
    status:       'completed',
    inputTokens,
    outputTokens,
    latencyMs:    Date.now() - start,
  })

  await ctx.setProgress(4, 4)

  return {
    policies_created: rows.length,
    policies_rejected: rejected.length,
    summary: result.summary,
  }
}
