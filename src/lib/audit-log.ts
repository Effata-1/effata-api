import { serviceClient } from './supabase'

export interface AuditEventParams {
  action:      string
  orgId:       string
  userId?:     string | null
  entityType?: string
  entityId?:   string
  details?:    Record<string, unknown>
}

export async function logAuditEvent(params: AuditEventParams): Promise<void> {
  try {
    await serviceClient.from('audit_logs').insert({
      org_id:      params.orgId,
      user_id:     params.userId     ?? null,
      user_email:  null,
      action:      params.action,
      entity_type: params.entityType ?? null,
      entity_id:   params.entityId   ?? null,
      entity_name: null,
      old_value:   null,
      new_value:   null,
      details:     params.details    ?? {},
    })
  } catch {
    // Fire-and-forget — never throw, never block the response
  }
}
