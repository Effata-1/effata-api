import { serviceClient } from '../../lib/supabase'
import { logAiRun } from '../../lib/ai-log'
import { reviewDlpCoverage } from '../../ai/agents/dlp-coverage-review'
import type { ProcessorContext } from '../job-config'

export async function coverageReviewProcessor(ctx: ProcessorContext): Promise<Record<string, unknown>> {
  const { orgId, userId } = ctx
  const start = Date.now()

  const { data: profile } = await serviceClient
    .from('onboarding_profiles')
    .select('tools, modules, coverage_areas, policy_presence, policy_mode, incident_review, data_categories, top_priorities')
    .eq('org_id', orgId)
    .maybeSingle()

  if (!profile) throw new Error('No onboarding profile found')

  const { data: channelRows } = await serviceClient
    .from('channel_coverage')
    .select('channel_slug, assessment_answers')
    .eq('org_id', orgId)

  const channelAnswers = Object.fromEntries(
    (channelRows ?? []).map((r: { channel_slug: string; assessment_answers: Record<string, string> }) =>
      [r.channel_slug, r.assessment_answers]
    )
  )

  await ctx.setProgress(1, 0)

  const { result, inputTokens, outputTokens } = await reviewDlpCoverage({
    tools:           profile.tools           ?? [],
    modules:         profile.modules         ?? {},
    coverage_areas:  profile.coverage_areas  ?? {},
    policy_presence: profile.policy_presence ?? null,
    policy_mode:     profile.policy_mode     ?? null,
    incident_review: profile.incident_review ?? null,
    data_categories: profile.data_categories ?? [],
    channelAnswers,
  })

  const { error } = await serviceClient.from('dlp_coverage_ai_reviews').insert({
    org_id:          orgId,
    review_type:     'background',
    coverage_score:  result.coverageScore,
    gaps:            result.gaps,
    recommendations: result.recommendations,
    reviewed_at:     new Date().toISOString(),
  })

  if (error) throw new Error(`Failed to save coverage review: ${error.message}`)

  void logAiRun({
    orgId,
    userId,
    agent:        'dlp-coverage-review',
    runType:      'user',
    status:       'completed',
    inputTokens,
    outputTokens,
    latencyMs:    Date.now() - start,
  })

  await ctx.setProgress(1, 1)

  return { coverage_score: result.coverageScore, gaps_count: result.gaps.length }
}
