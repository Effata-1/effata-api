import { Router } from 'express'
import { z } from 'zod'
import { requireRole } from '../../middleware/rbac'
import { serviceClient } from '../../lib/supabase'
import { logAuditEvent } from '../../lib/audit-log'
import { identifyApp, researchApp } from '../../ai/agents/genai-research'
import { computeTrustScore, classificationLabel } from '../../lib/genai-scoring'
import type { AppFields, DLPActivities, BreachInfo } from '../../lib/genai-scoring'

const router = Router()

const evaluateSchema = z.object({
  searchTerm: z.string().min(1).max(200),
})

const PROFILE_FRESHNESS_MS = 7 * 24 * 60 * 60 * 1000 // 7 days

interface IdentifiedApp {
  app_id:       string
  app_name:     string
  vendor:       string
  domain:       string
  app_type:     string
  logo_letter:  string
  logo_bg:      string
}

interface ResearchedProfile {
  fields:      AppFields
  dlp:         DLPActivities
  breach_info: BreachInfo
}

router.post('/evaluate', requireRole('analyst'), async (req, res, next) => {
  try {
    const parsed = evaluateSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors[0]?.message ?? 'Invalid input' })
    }

    const { searchTerm } = parsed.data
    const { orgId, userId } = req.context!

    // 1. Search catalog by exact app_id first, then by name
    const { data: existingApps } = await serviceClient
      .from('genai_apps')
      .select('app_id, app_name, vendor, domain, app_type, logo_letter, logo_bg, status')
      .or(`app_id.eq.${searchTerm.toLowerCase().replace(/\s+/g, '-')},app_name.ilike.%${searchTerm}%`)
      .eq('status', 'active')
      .limit(1)

    let app: IdentifiedApp
    let isNewToDb = false

    if (existingApps && existingApps.length > 0) {
      app = existingApps[0] as IdentifiedApp
    } else {
      // 2. Ask Claude to identify the app
      const { result } = await identifyApp(searchTerm)
      if (!result) {
        return res.json({ data: null })
      }

      const identified = result as IdentifiedApp

      // 3. Upsert into genai_apps
      const { data: inserted, error: upsertErr } = await serviceClient
        .from('genai_apps')
        .upsert(
          {
            ...identified,
            status:          'active',
            auto_researched: true,
            last_updated:    new Date().toISOString(),
          },
          { onConflict: 'app_id' },
        )
        .select('app_id, app_name, vendor, domain, app_type, logo_letter, logo_bg')
        .single()

      if (upsertErr || !inserted) {
        return next(new Error(upsertErr?.message ?? 'Failed to save app to catalog'))
      }

      app = inserted as IdentifiedApp
      isNewToDb = true
    }

    // 4. Check for existing profile and freshness
    const { data: existingProfile } = await serviceClient
      .from('genai_app_profiles')
      .select('app_id, fields, dlp, breach_info, updated_at')
      .eq('app_id', app.app_id)
      .maybeSingle()

    let fields: AppFields
    let dlp: DLPActivities
    let breach_info: BreachInfo

    const isFresh = existingProfile?.updated_at
      ? Date.now() - new Date(existingProfile.updated_at as string).getTime() < PROFILE_FRESHNESS_MS
      : false

    if (existingProfile && isFresh) {
      fields      = existingProfile.fields      as AppFields
      dlp         = existingProfile.dlp         as DLPActivities
      breach_info = existingProfile.breach_info as BreachInfo
    } else {
      // 5. Run AI research
      const { result: raw } = await researchApp({
        app_id:   app.app_id,
        app_name: app.app_name,
        vendor:   app.vendor,
        domain:   app.domain,
        app_type: app.app_type,
      })

      const researched = raw as ResearchedProfile

      // 6. Upsert profile
      const { error: profileErr } = await serviceClient
        .from('genai_app_profiles')
        .upsert(
          {
            app_id:      app.app_id,
            mode:        'personal',
            fields:      researched.fields,
            dlp:         researched.dlp,
            breach_info: researched.breach_info,
            updated_at:  new Date().toISOString(),
          },
          { onConflict: 'app_id,mode' },
        )

      if (profileErr) return next(new Error(profileErr.message ?? 'Failed to save app profile'))

      fields      = researched.fields
      dlp         = researched.dlp
      breach_info = researched.breach_info
    }

    // 7. Compute trust score
    const score = computeTrustScore(fields, dlp, breach_info)

    void logAuditEvent({
      action:     'genai_app.evaluated',
      orgId,
      userId,
      entityType: 'genai_app',
      entityId:   app.app_id,
      details:    { searchTerm, app_id: app.app_id, isNewToDb },
    })

    res.json({
      data: {
        app_id:                  app.app_id,
        app_name:                app.app_name,
        vendor:                  app.vendor,
        app_type:                app.app_type,
        logo_letter:             app.logo_letter,
        logo_bg:                 app.logo_bg,
        trustScore:              score.final_score,
        dlpActivitiesSupported:  score.dlp_activities_supported,
        dlpActivitiesTotal:      score.dlp_activities_total,
        suggestedClassification: classificationLabel(score.suggested_classification),
        isNewToDb,
      },
    })
  } catch (err) {
    next(err)
  }
})

export default router
