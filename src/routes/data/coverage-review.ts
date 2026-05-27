import { Router } from 'express'
import { requireRole } from '../../middleware/rbac'
import { serviceClient } from '../../lib/supabase'
import { logAuditEvent } from '../../lib/audit-log'
import { logAiRun } from '../../lib/ai-log'
import { reviewDlpCoverage } from '../../ai/agents/dlp-coverage-review'

const router = Router()

router.post('/', requireRole('analyst'), async (req, res, next) => {
  const start = Date.now()
  try {
    const { orgId, userId } = req.context!

    // Load org onboarding profile
    const { data: profile } = await serviceClient
      .from('onboarding_profiles')
      .select('tools, modules, coverage_areas, policy_presence, policy_mode, incident_review, data_categories, top_priorities')
      .eq('org_id', orgId)
      .maybeSingle()

    if (!profile) {
      return res.status(400).json({ error: 'No onboarding profile found — complete onboarding first.' })
    }

    // Load channel coverage assessment answers
    const { data: channelRows } = await serviceClient
      .from('channel_coverage')
      .select('channel_slug, assessment_answers')
      .eq('org_id', orgId)

    const channelAnswers = Object.fromEntries(
      (channelRows ?? []).map((r: { channel_slug: string; assessment_answers: Record<string, string> }) =>
        [r.channel_slug, r.assessment_answers]
      ),
    )

    // Run AI review
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

    // Store result
    const { error: insertErr } = await serviceClient
      .from('dlp_coverage_ai_reviews')
      .insert({
        org_id:          orgId,
        review_type:     'manual',
        coverage_score:  result.coverageScore,
        gaps:            result.gaps,
        recommendations: result.recommendations,
        reviewed_at:     new Date().toISOString(),
      })

    if (insertErr) return next(insertErr)

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

    void logAuditEvent({
      action:  'coverage_review.requested',
      orgId,
      userId,
      details: { source: 'user', coverage_score: result.coverageScore },
    })

    res.json({ ok: true, data: result })
  } catch (err) {
    void logAiRun({
      orgId:        req.context?.orgId ?? '',
      userId:       req.context?.userId ?? null,
      agent:        'dlp-coverage-review',
      runType:      'user',
      status:       'error',
      inputTokens:  0,
      outputTokens: 0,
      latencyMs:    Date.now() - start,
      error:        err instanceof Error ? err.message : String(err),
    })
    next(err)
  }
})

export default router
