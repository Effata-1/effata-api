import { anthropic, MODEL, AI_TIMEOUT_MS } from '../../lib/anthropic'
import { serviceClient } from '../../lib/supabase'

interface RegRow {
  id:               string
  code:             string
  short_name:       string
  summary:          string
  max_fine:         string | null
  last_verified_at: string
  requirements:     ReqRow[]
}

interface ReqRow {
  id:           string
  article:      string
  title:        string
  description:  string
  dlp_relevance: string
  fine:         string | null
  severity:     string
  dlp_controls: string[] | null
}

interface AIUpdate {
  changed:  boolean
  reason?:  string
  updates?: {
    summary?:    string
    max_fine?:   string | null
    requirements?: Array<{
      article:   string
      field:     'description' | 'dlp_relevance' | 'fine' | 'severity' | 'dlp_controls'
      new_value: string | string[] | null
    }>
  }
}

interface NewRegulation {
  code:           string
  short_name:     string
  name:           string
  regions:        string[]
  industries:     string[] | null
  jurisdiction:   string
  authority:      string | null
  type:           string
  summary:        string
  max_fine:       string | null
  effective_date: string | null
  source_url:     string
  requirements:   Array<{
    article:      string
    title:        string
    description:  string
    dlp_relevance: string
    fine:         string | null
    severity:     string
    dlp_controls: string[]
  }>
}

async function reviewRegulation(reg: RegRow): Promise<AIUpdate> {
  const reqFull = reg.requirements
    .map(r => `  • ${r.article} — ${r.title}\n    Description: ${r.description}\n    DLP Relevance: ${r.dlp_relevance}\n    Fine: ${r.fine ?? 'not specified'} | Severity: ${r.severity}\n    DLP Controls: ${r.dlp_controls?.join(', ') ?? 'none'}`)
    .join('\n\n')

  const prompt = `You are auditing stored compliance regulation data. You may correct ANY field — but ONLY when you are 100% certain the stored content is factually wrong, not just differently worded.

Regulation: ${reg.short_name} (${reg.code})
Summary stored: ${reg.summary}
Max fine stored: ${reg.max_fine ?? 'not specified'}

Requirements stored:
${reqFull}

STRICT RULES — violating these corrupts production data:
1. Return changed=false unless you are 100% certain a stored value is objectively incorrect.
2. Do NOT rewrite descriptions or DLP relevance just because you'd word it differently.
3. Do NOT change severity unless the regulation explicitly defines a different risk tier.
4. Do NOT change fine amounts unless the stored number is provably wrong.
5. Prefer changed=false. One wrong update is worse than missing a minor inaccuracy.

Valid dlp_controls values: data_classification, dlp_web, dlp_email, dlp_endpoint, dlp_saas, genai_controls, audit_logging, breach_detection, encryption_transit, access_controls

Respond ONLY with valid JSON: {"changed": false} or {"changed": true, "reason": "...", "updates": {...}}`

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)
  try {
    const message = await anthropic.messages.create(
      { model: MODEL, max_tokens: 1024, messages: [{ role: 'user', content: prompt }] },
      { signal: controller.signal },
    )
    const text = message.content[0].type === 'text' ? message.content[0].text.trim() : '{}'
    const match = text.match(/\{[\s\S]*\}/)
    if (!match) return { changed: false }
    return JSON.parse(match[0]) as AIUpdate
  } catch {
    return { changed: false }
  } finally {
    clearTimeout(timer)
  }
}

async function discoverNewRegulations(existingCodes: string[]): Promise<NewRegulation[]> {
  const prompt = `You are a DLP compliance expert. Your task is to identify DLP-relevant regulations that are NOT in the list below.

Already tracked regulations (do NOT suggest these):
${existingCodes.join(', ')}

Identify up to 3 enacted regulations or compliance frameworks that are directly relevant to Data Loss Prevention, already in force, and NOT in the list above.

Only include regulations you are highly confident about. If none are missing, return an empty array.

Respond ONLY with valid JSON:
{
  "new_regulations": [
    {
      "code": "short_snake_case_id",
      "short_name": "Acronym",
      "name": "Full Official Name",
      "regions": ["Region name"],
      "industries": null,
      "jurisdiction": "Country or region",
      "authority": "Regulating body name",
      "type": "privacy|security|sector|framework|standard|ai_governance",
      "summary": "2-3 sentence plain-English summary of what it requires from a DLP perspective",
      "max_fine": "e.g. €10M or 2% global ARR (or null)",
      "effective_date": "YYYY-MM-DD (or null)",
      "source_url": "official government/regulator URL",
      "requirements": [
        {
          "article": "Article or Section reference",
          "title": "Short requirement title",
          "description": "What the regulation requires",
          "dlp_relevance": "How DLP controls address this requirement",
          "fine": "Specific fine for this article (or null)",
          "severity": "critical|high|medium",
          "dlp_controls": ["data_classification", "dlp_web"]
        }
      ]
    }
  ]
}`

  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), AI_TIMEOUT_MS)
  try {
    const message = await anthropic.messages.create(
      { model: MODEL, max_tokens: 4096, messages: [{ role: 'user', content: prompt }] },
      { signal: controller.signal },
    )
    const text = message.content[0].type === 'text' ? message.content[0].text.trim() : '{}'
    const match = text.match(/\{[\s\S]*\}/)
    if (!match) return []
    const parsed = JSON.parse(match[0]) as { new_regulations?: NewRegulation[] }
    return parsed.new_regulations ?? []
  } catch {
    return []
  } finally {
    clearTimeout(timer)
  }
}

export interface ComplianceRunResult {
  run_id:       string
  regs_checked: number
  regs_updated: number
  regs_added:   number
  changes:      Array<{ regulation_code: string; regulation_name: string; reason: string; fields_updated: string[] }>
  errors:       Array<{ regulation_code?: string; error: string }>
}

export async function runComplianceCheck(): Promise<ComplianceRunResult> {
  const { data: run, error: runError } = await serviceClient
    .from('compliance_check_runs')
    .insert({ status: 'running' })
    .select('id')
    .single()

  if (runError || !run) throw new Error('Failed to create run record')
  const runId: string = (run as { id: string }).id

  const changes: ComplianceRunResult['changes'] = []
  const errors:  ComplianceRunResult['errors']  = []
  let regsUpdated = 0
  let regsAdded   = 0

  try {
    const { data: regsData } = await serviceClient
      .from('compliance_regulations')
      .select('*, requirements:compliance_requirements(*)')
      .eq('active', true)

    const regs = (regsData as RegRow[]) ?? []

    // Review existing regulations in batches of 5
    const BATCH = 5
    for (let i = 0; i < regs.length; i += BATCH) {
      const batch = regs.slice(i, i + BATCH)
      await Promise.all(batch.map(async reg => {
        try {
          const result = await reviewRegulation(reg)
          if (!result.changed || !result.updates) {
            await serviceClient
              .from('compliance_regulations')
              .update({ last_verified_at: new Date().toISOString() })
              .eq('id', reg.id)
            return
          }

          const fieldsUpdated: string[] = []
          const now = new Date().toISOString()
          const regUpdate: Record<string, unknown> = { last_verified_at: now, content_updated_at: now }

          if (result.updates.summary !== undefined) { regUpdate.summary = result.updates.summary; fieldsUpdated.push('summary') }
          if ('max_fine' in result.updates) { regUpdate.max_fine = result.updates.max_fine; fieldsUpdated.push('max_fine') }

          await serviceClient.from('compliance_regulations').update(regUpdate).eq('id', reg.id)

          if (result.updates.requirements?.length) {
            for (const reqUpdate of result.updates.requirements) {
              const matched = reg.requirements.find(r => r.article === reqUpdate.article)
              if (!matched) continue
              await serviceClient
                .from('compliance_requirements')
                .update({ [reqUpdate.field]: reqUpdate.new_value })
                .eq('id', matched.id)
              fieldsUpdated.push(`${reqUpdate.article}.${reqUpdate.field}`)
            }
          }

          await serviceClient.from('compliance_verification_log').insert({
            regulation_id: reg.id,
            org_id:        '00000000-0000-0000-0000-000000000000',
            verified_by:   null,
            changed:       true,
            notes:         `AI review: ${result.reason}`,
            changes:       { source: 'ai_cron', run_id: runId, updates: result.updates },
          })

          changes.push({ regulation_code: reg.code, regulation_name: reg.short_name, reason: result.reason ?? '', fields_updated: fieldsUpdated })
          regsUpdated++
        } catch (err) {
          errors.push({ regulation_code: reg.code, error: err instanceof Error ? err.message : String(err) })
        }
      }))
    }

    // Discover new regulations
    try {
      const existingCodes = regs.map(r => r.code)
      const newRegs = await discoverNewRegulations(existingCodes)
      for (const nr of newRegs) {
        if (existingCodes.includes(nr.code)) continue
        const { data: inserted, error: insertErr } = await serviceClient
          .from('compliance_regulations')
          .insert({ code: nr.code, short_name: nr.short_name, name: nr.name, regions: nr.regions, industries: nr.industries, jurisdiction: nr.jurisdiction, authority: nr.authority, type: nr.type, summary: nr.summary, max_fine: nr.max_fine, effective_date: nr.effective_date, source_url: nr.source_url, active: true })
          .select('id')
          .single()
        if (insertErr || !inserted) { errors.push({ regulation_code: nr.code, error: insertErr?.message ?? 'Insert failed' }); continue }
        if (nr.requirements.length > 0) {
          await serviceClient.from('compliance_requirements').insert(
            nr.requirements.map(req => ({ regulation_id: (inserted as { id: string }).id, article: req.article, title: req.title, description: req.description, dlp_relevance: req.dlp_relevance, fine: req.fine, severity: req.severity, dlp_controls: req.dlp_controls }))
          )
        }
        changes.push({ regulation_code: nr.code, regulation_name: nr.short_name, reason: 'New regulation discovered', fields_updated: ['all'] })
        regsAdded++
      }
    } catch (err) {
      errors.push({ error: `Discover step failed: ${err instanceof Error ? err.message : String(err)}` })
    }

    await serviceClient
      .from('compliance_check_runs')
      .update({ status: 'completed', completed_at: new Date().toISOString(), regs_checked: regs.length, regs_updated: regsUpdated, regs_added: regsAdded, changes, errors })
      .eq('id', runId)

    return { run_id: runId, regs_checked: regs.length, regs_updated: regsUpdated, regs_added: regsAdded, changes, errors }
  } catch (err) {
    await serviceClient.from('compliance_check_runs').update({ status: 'failed', completed_at: new Date().toISOString() }).eq('id', runId)
    throw err
  }
}
