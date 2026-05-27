import { Router } from 'express'
import { z } from 'zod'
import { requireRole } from '../../middleware/rbac'
import { serviceClient } from '../../lib/supabase'
import { logAuditEvent } from '../../lib/audit-log'
import { config } from '../../config'

const router = Router()

const inviteSchema = z.object({
  email: z.string().email(),
  role:  z.enum(['admin', 'analyst', 'read_only']),
})

router.get('/', requireRole('admin'), async (req, res, next) => {
  try {
    const { orgId } = req.context!

    const [profilesResult, usersResult] = await Promise.all([
      serviceClient
        .from('profiles')
        .select('id, full_name, role, created_at')
        .eq('org_id', orgId)
        .order('created_at', { ascending: true }),
      serviceClient.auth.admin.listUsers(),
    ])

    if (profilesResult.error) return next(profilesResult.error)
    if (usersResult.error)    return next(usersResult.error)

    const emailMap = new Map(
      usersResult.data.users.map(u => [u.id, u.email ?? null])
    )

    res.json(
      (profilesResult.data ?? []).map(p => ({
        id:         p.id,
        full_name:  p.full_name,
        role:       p.role,
        created_at: p.created_at,
        email:      emailMap.get(p.id) ?? null,
      }))
    )
  } catch (err) {
    next(err)
  }
})

router.post('/invite', requireRole('admin'), async (req, res, next) => {
  try {
    const parsed = inviteSchema.safeParse(req.body)
    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.errors[0]?.message ?? 'Invalid input' })
    }

    const { email, role } = parsed.data
    const { orgId, userId } = req.context!

    // Check if this email already belongs to an org member
    const { data: { users }, error: listErr } = await serviceClient.auth.admin.listUsers()
    if (listErr) return next(listErr)

    const existingUser = users.find(u => u.email === email)
    if (existingUser) {
      const { count } = await serviceClient
        .from('profiles')
        .select('id', { count: 'exact', head: true })
        .eq('id', existingUser.id)
        .eq('org_id', orgId)

      if ((count ?? 0) > 0) {
        return res.status(409).json({ error: 'User is already a member of this organisation' })
      }
    }

    const { error: inviteErr } = await serviceClient.auth.admin.inviteUserByEmail(email, {
      ...(config.SITE_URL && { redirectTo: `${config.SITE_URL}/auth/callback` }),
      data: { org_id: orgId, role },
    })
    if (inviteErr) return res.status(400).json({ error: inviteErr.message })

    void logAuditEvent({
      action:     'team.member_invited',
      orgId,
      userId,
      details:    { email, role },
    })

    res.json({ ok: true })
  } catch (err) {
    next(err)
  }
})

export default router
