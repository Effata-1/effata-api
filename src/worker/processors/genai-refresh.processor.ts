import { serviceClient } from '../../lib/supabase'
import { logAiRun } from '../../lib/ai-log'
import { discoverNewApps, researchApp } from '../../ai/agents/genai-research'
import { parseFields, parseDLP, parseBreach } from '../../lib/genai-scoring'
import type { ProcessorContext } from '../job-config'

interface GenaiApp {
  app_id:      string
  app_name:    string
  vendor:      string
  domain:      string
  app_type:    string
  logo_letter: string
  logo_bg:     string
  status:      string
}

interface FieldChange {
  app_id:    string
  app_name:  string
  field:     string
  old_value: string
  new_value: string
}

function diffProfiles(
  appId:    string,
  appName:  string,
  oldObj:   Record<string, string>,
  newObj:   Record<string, string>,
  prefix = '',
): FieldChange[] {
  return Object.entries(newObj)
    .filter(([key, newVal]) => oldObj[key] && oldObj[key] !== newVal)
    .map(([key, newVal]) => ({ app_id: appId, app_name: appName, field: prefix + key, old_value: oldObj[key], new_value: newVal }))
}

export async function genaiRefreshProcessor(ctx: ProcessorContext): Promise<Record<string, unknown>> {
  const start = Date.now()

  // Mark stale running research runs as timed_out
  await serviceClient
    .from('genai_research_runs')
    .update({ status: 'timed_out', completed_at: new Date().toISOString() })
    .eq('status', 'running')
    .lt('started_at', new Date(Date.now() - 10 * 60_000).toISOString())

  // Create a research run log
  const { data: run, error: runError } = await serviceClient
    .from('genai_research_runs')
    .insert({ status: 'running' })
    .select('id')
    .single()

  if (runError || !run) throw new Error('Failed to create research run log')
  const runId: string = run.id

  const errors: Array<{ app_id: string; error: string }> = []
  const allChanges: FieldChange[] = []
  let appsUpdated = 0
  let appsAdded   = 0
  let appsSkipped = 0
  let totalInputTokens  = 0
  let totalOutputTokens = 0

  try {
    const { data: existingRows } = await serviceClient
      .from('genai_apps')
      .select('app_id, app_name, vendor, domain, app_type, logo_letter, logo_bg, status')
      .eq('status', 'active')

    const allApps: GenaiApp[] = (existingRows ?? []) as GenaiApp[]
    const existingIds = allApps.map(a => a.app_id)

    // Discover new apps
    const { result: newAppCandidates, inputTokens: discoverIn, outputTokens: discoverOut } =
      await discoverNewApps(existingIds)
    totalInputTokens  += discoverIn
    totalOutputTokens += discoverOut

    const newApps = (newAppCandidates as Array<Record<string, unknown>>)
      .filter(item => typeof item.app_id === 'string' && typeof item.app_name === 'string')
      .filter(item => !(existingIds.includes(item.app_id as string)))
      .slice(0, 5)
      .map(item => ({
        app_id:      (item.app_id as string).toLowerCase().replace(/\s+/g, '-'),
        app_name:    item.app_name as string,
        vendor:      (item.vendor as string) ?? '',
        domain:      (item.domain as string) ?? '',
        app_type:    (item.app_type as string) ?? 'AI Assistant',
        logo_letter: ((item.logo_letter as string) ?? (item.app_name as string).charAt(0)).charAt(0).toUpperCase(),
        logo_bg:     (item.logo_bg as string) ?? '#1a1a2e',
      }))

    for (const app of newApps) {
      const { error: insertError } = await serviceClient.from('genai_apps').insert({
        app_id:          app.app_id,
        app_name:        app.app_name,
        vendor:          app.vendor,
        domain:          app.domain,
        app_type:        app.app_type,
        logo_letter:     app.logo_letter,
        logo_bg:         app.logo_bg,
        status:          'active',
        auto_researched: true,
        last_updated:    new Date().toISOString(),
      })
      if (insertError) {
        errors.push({ app_id: app.app_id, error: `Insert failed: ${insertError.message}` })
      } else {
        allApps.push({ ...app, status: 'active' })
        appsAdded++
      }
    }

    // Set total_items now that we know the full list
    await ctx.setProgress(allApps.length, 0)

    // Research each app
    for (const app of allApps) {
      try {
        const { data: existing } = await serviceClient
          .from('genai_app_profiles')
          .select('fields, dlp')
          .eq('app_id', app.app_id)
          .maybeSingle()

        const { result: raw, inputTokens, outputTokens } = await researchApp(app)
        totalInputTokens  += inputTokens
        totalOutputTokens += outputTokens

        const profile = raw as { fields: Record<string, unknown>; dlp: Record<string, unknown>; breach_info: Record<string, unknown>; notes: string }
        const fields      = parseFields(profile.fields)
        const dlp         = parseDLP(profile.dlp)
        const breach_info = parseBreach(profile.breach_info)

        if (existing) {
          allChanges.push(
            ...diffProfiles(app.app_id, app.app_name, existing.fields as Record<string, string>, fields as unknown as Record<string, string>),
            ...diffProfiles(app.app_id, app.app_name, existing.dlp   as Record<string, string>, dlp   as unknown as Record<string, string>, 'dlp.'),
          )
        }

        const { error: upsertErr } = await serviceClient
          .from('genai_app_profiles')
          .upsert(
            { app_id: app.app_id, mode: 'personal', fields, dlp, breach_info },
            { onConflict: 'app_id,mode' },
          )

        if (upsertErr) {
          errors.push({ app_id: app.app_id, error: `Upsert: ${upsertErr.message}` })
        } else {
          await serviceClient.from('genai_apps').update({
            last_updated:    new Date().toISOString(),
            auto_researched: true,
            research_notes:  typeof profile.notes === 'string' ? profile.notes : '',
          }).eq('app_id', app.app_id)

          appsUpdated++
        }
      } catch (err) {
        errors.push({ app_id: app.app_id, error: err instanceof Error ? err.message : String(err) })
      }

      await ctx.setProgress(allApps.length, appsUpdated + errors.length)
    }

    const finalStatus =
      appsSkipped > 0                                    ? 'partial'
      : errors.length > 0 && appsUpdated === 0           ? 'failed'
      : 'completed'

    await serviceClient.from('genai_research_runs').update({
      completed_at: new Date().toISOString(),
      apps_checked: allApps.length,
      apps_updated: appsUpdated,
      apps_added:   appsAdded,
      errors,
      changes:      allChanges,
      status:       finalStatus,
    }).eq('id', runId)

    void logAiRun({
      orgId:        ctx.orgId,
      userId:       ctx.userId,
      agent:        'genai-refresh',
      runType:      'cron',
      status:       finalStatus === 'failed' ? 'error' : 'completed',
      inputTokens:  totalInputTokens,
      outputTokens: totalOutputTokens,
      latencyMs:    Date.now() - start,
    })

    return {
      status:       finalStatus,
      apps_updated: appsUpdated,
      apps_added:   appsAdded,
      apps_skipped: appsSkipped,
      changes:      allChanges.length,
      errors,
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    await serviceClient.from('genai_research_runs').update({
      completed_at: new Date().toISOString(),
      status:       'failed',
      errors:       [{ error: msg }],
    }).eq('id', runId)
    throw err
  }
}
