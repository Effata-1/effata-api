import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { translate } from './skyhigh.adapter'
import { FIXTURES, MOCK_REGISTRY } from './test-fixtures'

describe('skyhigh adapter', () => {
  test('secret upload block — always emits 2 policies: Inline Proxy + API-driven', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY)
    assert.equal(result.vendor, 'skyhigh-security')
    assert.equal(result.status, 'partial')
    assert.equal(result.native_policies.length, 2, 'Skyhigh must emit Inline Proxy + API-driven policies')

    const inline = result.native_policies[0] as Record<string, unknown>
    const api    = result.native_policies[1] as Record<string, unknown>
    assert.ok((inline.mode as string).includes('Inline'), 'First policy must be Inline Proxy')
    assert.ok((api.mode as string).includes('API'), 'Second policy must be API-driven')
  })

  test('secret upload block — inline rule group has Block action and Critical severity', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY)
    const inline = result.native_policies[0] as Record<string, unknown>
    const ruleGroup = (inline.rule_groups as Record<string, unknown>[])[0]
    assert.equal(ruleGroup.severity, 'Critical')
    assert.ok((ruleGroup.actions as string[]).some(a => a === 'Block'), 'Block action missing in inline rule group')
  })

  test('confidential coach — inline rule group has coaching action', () => {
    const result = translate(FIXTURES.confidentialCoach, MOCK_REGISTRY)
    const inline = result.native_policies[0] as Record<string, unknown>
    const ruleGroup = (inline.rule_groups as Record<string, unknown>[])[0]
    assert.equal(ruleGroup.severity, 'High')
    assert.ok(
      (ruleGroup.actions as string[]).some(a => a.toLowerCase().includes('coach')),
      'Coach action missing in inline rule group',
    )
    assert.ok(result.mapping_report.lossy_mappings.some(m => m.toLowerCase().includes('coach')))
  })

  test('approved use allow — unverified_vendor_areas contains allow scope warning', () => {
    const result = translate(FIXTURES.approvedUseAllow, MOCK_REGISTRY)
    assert.ok(
      result.mapping_report.unverified_vendor_areas.some(u => u.toLowerCase().includes('allow')),
      'Allow scope warning missing in unverified_vendor_areas',
    )
  })

  test('label detection upload only — AIP label condition in inline policy', () => {
    const result = translate(FIXTURES.labelDetectionUploadOnly, MOCK_REGISTRY)
    const inline = result.native_policies[0] as Record<string, unknown>
    const ruleGroup = (inline.rule_groups as Record<string, unknown>[])[0]
    const conditions = ruleGroup.conditions as string[]
    assert.ok(
      conditions.some(c => c.toLowerCase().includes('label')),
      'AIP label condition missing for clabel: data type',
    )
    assert.ok(result.mapping_report.exact_mappings.some(m => m.toLowerCase().includes('label')))
  })

  test('post prompt monitor — upload/post activity in inline scope', () => {
    const result = translate(FIXTURES.postPromptMonitor, MOCK_REGISTRY)
    const inline = result.native_policies[0] as Record<string, unknown>
    const scope  = inline.scope as Record<string, unknown>
    assert.ok((scope.activities as string[]).some(a => a.includes('post')), 'Post activity missing in inline scope')
  })

  test('scope_all_apps: true — services uses All GenAI applications', () => {
    const result = translate(FIXTURES.scopeAllApps, MOCK_REGISTRY)
    const inline = result.native_policies[0] as Record<string, unknown>
    const scope  = inline.scope as Record<string, unknown>
    assert.ok(
      (scope.services as string[]).some(s => s.toLowerCase().includes('generative ai')),
      'GenAI services target missing',
    )
  })

  test('scope_app_ids specific — services uses named apps', () => {
    const result = translate(FIXTURES.scopeSpecificApps, MOCK_REGISTRY)
    const inline = result.native_policies[0] as Record<string, unknown>
    const scope  = inline.scope as Record<string, unknown>
    assert.deepEqual(scope.services, ['chatgpt', 'claude', 'gemini'])
  })

  test('lossy_mappings always contains split policy note', () => {
    for (const fixture of Object.values(FIXTURES)) {
      const result = translate(fixture, MOCK_REGISTRY)
      assert.ok(
        result.mapping_report.lossy_mappings.some(m => m.toLowerCase().includes('split')),
        `Split policy note missing for fixture ${fixture.id}`,
      )
    }
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
