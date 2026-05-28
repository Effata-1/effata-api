import Anthropic from '@anthropic-ai/sdk'
import { config } from '../config'

export const anthropic = new Anthropic({ apiKey: config.ANTHROPIC_API_KEY })

export const MODEL = 'claude-sonnet-4-6'
export const AI_TIMEOUT_MS = 90_000
