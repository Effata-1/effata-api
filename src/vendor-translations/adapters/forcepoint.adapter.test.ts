import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { translate } from './forcepoint.adapter'
import { FIXTURES, MOCK_REGISTRY } from './test-fixtures'

describe('forcepoint adapter', () => {
  test('secret upload block — emits one policy with Block action and Critical severity', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY)
    assert.equal(result.vendor, 'forcepoint-dlp')
    assert.ok(result.native_policies.length === 1, 'Forcepoint should emit a single policy')

    const policy = result.native_policies[0] as Record<string, unknown>
    const actions = policy.action as string[]
    assert.ok(actions.includes('Block'), 'Block action missing')
    assert.equal(policy.severity, 'Critical')
    assert.ok(actions.includes('Create Incident'))
    assert.ok(actions.includes('Export Evidence'))
  })

  test('confidential coach — Coach action and High severity', () => {
    const result = translate(FIXTURES.confidentialCoach, MOCK_REGISTRY)
    const policy = result.native_policies[0] as Record<string, unknown>
    assert.equal(policy.severity, 'High')
    assert.ok((policy.action as string[]).includes('Coach'))
  })

  test('approved use allow — Allow action, scope warning in tests_required', () => {
    const result = translate(FIXTURES.approvedUseAllow, MOCK_REGISTRY)
    const policy = result.native_policies[0] as Record<string, unknown>
    assert.ok((policy.action as string[]).includes('Allow'))
    assert.ok(
      result.mapping_report.tests_required.some(t => t.toLowerCase().includes('allow')),
      'Allow scope test warning missing',
    )
  })

  test('label detection upload only — post_prompt = not-set so upload is the action driver', () => {
    const result = translate(FIXTURES.labelDetectionUploadOnly, MOCK_REGISTRY)
    const policy = result.native_policies[0] as Record<string, unknown>
    // primary_action = 'block' and upload = 'block' → Block
    assert.ok((policy.action as string[]).includes('Block'))
    assert.ok(
      result.mapping_report.unverified_vendor_areas.some(u => u.toLowerCase().includes('label')),
      'Label unverified area warning missing',
    )
  })

  test('post prompt monitor — Monitor action and Medium severity', () => {
    const result = translate(FIXTURES.postPromptMonitor, MOCK_REGISTRY)
    const policy = result.native_policies[0] as Record<string, unknown>
    assert.equal(policy.severity, 'Medium')
    assert.ok((policy.action as string[]).includes('Monitor'))
  })

  test('scope_all_apps: true — destination_resources contains GenAI group, lossy mapping added', () => {
    const result = translate(FIXTURES.scopeAllApps, MOCK_REGISTRY)
    const policy = result.native_policies[0] as Record<string, unknown>
    const dest = policy.destination_resources as string[]
    assert.ok(dest.some(d => d.toLowerCase().includes('genai')), 'GenAI destination group missing')
    assert.ok(result.mapping_report.lossy_mappings.length > 0, 'Lossy mapping missing for scope_all_apps')
  })

  test('scope_app_ids specific — destination_resources uses named apps', () => {
    const result = translate(FIXTURES.scopeSpecificApps, MOCK_REGISTRY)
    const policy = result.native_policies[0] as Record<string, unknown>
    const dest = policy.destination_resources as string[]
    assert.deepEqual(dest, ['chatgpt', 'claude', 'gemini'])
  })

  test('mapping_report fields are always present', () => {
    for (const fixture of Object.values(FIXTURES)) {
      const result = translate(fixture, MOCK_REGISTRY)
      assert.ok(Array.isArray(result.mapping_report.exact_mappings))
      assert.ok(Array.isArray(result.mapping_report.lossy_mappings))
      assert.ok(Array.isArray(result.mapping_report.unsupported_intent))
      assert.ok(Array.isArray(result.mapping_report.unverified_vendor_areas))
      assert.ok(Array.isArray(result.mapping_report.tests_required))
    }
  })
})
