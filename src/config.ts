import { z } from 'zod'

const envSchema = z.object({
  ANTHROPIC_API_KEY:       z.string().min(1),
  SUPABASE_URL:            z.string().url(),
  SUPABASE_ANON_KEY:       z.string().min(1),
  SUPABASE_SERVICE_ROLE_KEY: z.string().min(1),
  ALLOWED_ORIGINS:         z.string().min(1).default('http://localhost:3000'),
  SITE_URL:                z.string().url().optional(),
  CRON_API_KEY:            z.string().min(1),
  INTERNAL_API_SECRET:     z.string().min(1).optional(),
  PORT:                    z.coerce.number().default(3001),
})

const parsed = envSchema.safeParse(process.env)

if (!parsed.success) {
  console.error('❌ Missing or invalid environment variables:')
  console.error(parsed.error.flatten().fieldErrors)
  process.exit(1)
}

export const config = parsed.data
