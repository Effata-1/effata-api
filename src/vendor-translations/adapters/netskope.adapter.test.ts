import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { translate } from './netskope.adapter'
import { FIXTURES, MOCK_REGISTRY } from './test-fixtures'

describe('netskope adapter', () => {
  test('secret upload block — action is Block, upload activity present', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY)
    assert.equal(result.vendor, 'netskope')
    assert.ok(['success', 'partial'].includes(result.status))
    assert.ok(result.native_policies.length >= 1)

    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy, 'main [DLP] policy missing')
    assert.equal(mainPolicy.action, 'Block')
    assert.ok((mainPolicy.activities as string[]).includes('Upload'), 'Upload activity missing')
    assert.ok(result.mapping_report.exact_mappings.length > 0)
  })

  test('confidential coach — action is Coach, notification_template set', () => {
    const result = translate(FIXTURES.confidentialCoach, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy, 'main [DLP] policy missing')
    assert.equal(mainPolicy.action, 'Coach')
    assert.ok(typeof mainPolicy.notification_template === 'string', 'notification_template missing for coach')
  })

  test('approved use allow — scoped Allow rule emitted first, tests_required contains scope warning', () => {
    const result = translate(FIXTURES.approvedUseAllow, MOCK_REGISTRY)
    const allowPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[Allow]')) as Record<string, unknown>
    assert.ok(allowPolicy, '[Allow] policy missing')
    assert.equal(allowPolicy.action, 'Allow')
    assert.ok(
      result.mapping_report.tests_required.some(t => t.toLowerCase().includes('allow')),
      'No allow scope warning in tests_required',
    )
  })

  test('label detection upload only — post_prompt = not-set means no Post bypass without block rule', () => {
    const result = translate(FIXTURES.labelDetectionUploadOnly, MOCK_REGISTRY)
    // clabel: data type should add to lossy_mappings
    assert.ok(result.mapping_report.lossy_mappings.some(m => m.toLowerCase().includes('label')), 'label lossy mapping missing')
    assert.equal(result.status, 'partial')
  })

  test('post prompt monitor — Post activity present', () => {
    const result = translate(FIXTURES.postPromptMonitor, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy)
    assert.ok((mainPolicy.activities as string[]).includes('Post'), 'Post activity missing for post_prompt monitor')
  })

  test('scope_all_apps: true — destination uses app_categories not apps', () => {
    const result = translate(FIXTURES.scopeAllApps, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy)
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.ok(dest.app_categories, 'app_categories missing for scope_all_apps')
    assert.ok(!dest.apps, 'apps should not be present when scope_all_apps')
  })

  test('scope_app_ids specific — destination uses named apps list', () => {
    const result = translate(FIXTURES.scopeSpecificApps, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy)
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.ok(Array.isArray(dest.apps), 'apps list missing for scope_app_ids')
    assert.deepEqual(dest.apps, ['chatgpt', 'claude', 'gemini'])
  })

  test('all policies have source, severity, status, dlp_profile fields', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy.source, 'source missing')
    assert.ok((mainPolicy.source as Record<string, unknown>).users_or_groups, 'source.users_or_groups missing')
    assert.ok(mainPolicy.severity, 'severity missing')
    assert.equal(mainPolicy.status, 'enabled')
    assert.equal(mainPolicy.severity, 'Critical', 'block should map to Critical severity')
    assert.ok('dlp_profile' in mainPolicy, 'dlp_profile field missing')
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
