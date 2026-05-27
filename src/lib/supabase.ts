import { createClient } from '@supabase/supabase-js'
import { config } from '../config'

export const serviceClient = createClient(
  config.SUPABASE_URL,
  config.SUPABASE_SERVICE_ROLE_KEY,
  { auth: { autoRefreshToken: false, persistSession: false } },
)
