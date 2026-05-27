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
    const { error } = await serviceClient.from('audit_logs').insert({
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
    if (error) console.error('[audit-log] insert failed:', error.message, '| action:', params.action)
  } catch (err) {
    console.error('[audit-log] exception:', err instanceof Error ? err.message : err, '| action:', params.action)
  }
}
