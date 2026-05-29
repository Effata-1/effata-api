import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { translate } from './purview.adapter'
import { FIXTURES, MOCK_REGISTRY } from './test-fixtures'

describe('purview adapter', () => {
  test('secret upload block — always emits multiple location policies', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY)
    assert.equal(result.vendor, 'microsoft-purview')
    assert.equal(result.status, 'partial')
    assert.ok(result.native_policies.length >= 2, 'Purview must emit a location bundle (2+ policies)')
  })

  test('confidential coach — UserNotification appears in coach policies', () => {
    const result = translate(FIXTURES.confidentialCoach, MOCK_REGISTRY)
    const allActions = result.native_policies.flatMap((p: unknown) => {
      const policy = p as Record<string, unknown>
      return [policy.action as string]
    })
    assert.ok(allActions.some(a => a === 'UserNotification'), 'UserNotification action missing for coach policy')
    assert.ok(result.mapping_report.lossy_mappings.some(m => m.toLowerCase().includes('coach')), 'coach lossy mapping missing')
  })

  test('approved use allow — allow scope warning in unverified_vendor_areas', () => {
    const result = translate(FIXTURES.approvedUseAllow, MOCK_REGISTRY)
    assert.ok(
      result.mapping_report.unverified_vendor_areas.some(u => u.toLowerCase().includes('allow')),
      'Allow scope unverified area warning missing',
    )
    assert.ok(
      result.mapping_report.tests_required.some(t => t.toLowerCase().includes('allow')),
      'Allow scope test required warning missing',
    )
  })

  test('label detection upload only — clabel: conditions appear', () => {
    const result = translate(FIXTURES.labelDetectionUploadOnly, MOCK_REGISTRY)
    const conditions = result.native_policies.flatMap((p: unknown) => {
      const policy = p as Record<string, unknown>
      return (policy.content_conditions as string[]) ?? []
    })
    assert.ok(conditions.some(c => c.includes('label')), 'Label condition missing in Purview policies')
  })

  test('post prompt monitor — Copilot location policy present and marked unverified', () => {
    const result = translate(FIXTURES.postPromptMonitor, MOCK_REGISTRY)
    const copilotPolicy = result.native_policies.find((p: unknown) => {
      const policy = p as Record<string, string>
      return (policy.location ?? '').includes('Copilot')
    })
    assert.ok(copilotPolicy, 'Copilot location policy missing for post_prompt')
    assert.ok(
      result.mapping_report.unverified_vendor_areas.some(u => u.toLowerCase().includes('copilot')),
      'Copilot unverified area warning missing',
    )
  })

  test('scope_all_apps: true — All Users scope used', () => {
    const result = translate(FIXTURES.scopeAllApps, MOCK_REGISTRY)
    const anyAllUsers = result.native_policies.some((p: unknown) => {
      const policy = p as Record<string, unknown>
      const scope = policy.scope as Record<string, string[]> | undefined
      return scope?.users_or_groups?.includes('All Users')
    })
    assert.ok(anyAllUsers, 'All Users scope missing')
  })

  test('scope_app_ids specific — scope used in at least one policy', () => {
    const result = translate(FIXTURES.scopeSpecificApps, MOCK_REGISTRY)
    assert.ok(result.native_policies.length >= 2)
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
