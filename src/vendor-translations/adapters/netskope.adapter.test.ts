import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { translate } from './netskope.adapter'
import { FIXTURES, MOCK_REGISTRY } from './test-fixtures'

describe('netskope adapter', () => {
  test('secret upload block — main policy has simple profile_action with Block and Upload activity', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY)
    assert.equal(result.vendor, 'netskope')
    assert.ok(['success', 'partial'].includes(result.status))

    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy, 'main [DLP] policy missing')

    // Activities are inside destination
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.ok((dest.activities as string[]).includes('Upload'), 'Upload activity missing from destination')

    // Profile & Action — simple object (one action for all profiles), no per-profile table
    const profileAction = mainPolicy.profile_action as Record<string, unknown> | null
    assert.ok(profileAction !== null, 'profile_action must be set when label is present')
    assert.ok(Array.isArray(profileAction!.dlp_profiles), 'dlp_profiles must be an array')
    assert.equal(profileAction!.action, 'Block')

    // No traffic_action by default — it is not mandatory
    assert.ok(!('traffic_action' in mainPolicy), 'traffic_action must not be emitted by default')

    assert.ok(result.mapping_report.exact_mappings.length > 0)
  })

  test('confidential coach — profile_action has Coach + notification_template', () => {
    const result = translate(FIXTURES.confidentialCoach, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy, 'main [DLP] policy missing')
    const profileAction = mainPolicy.profile_action as Record<string, unknown> | null
    assert.ok(profileAction, 'profile_action missing')
    assert.equal(profileAction!.action, 'Coach')
    assert.ok(typeof profileAction!.notification_template === 'string', 'notification_template missing for coach')
  })

  test('approved use allow — scoped Allow rule emitted first, tests_required contains scope warning', () => {
    const result = translate(FIXTURES.approvedUseAllow, MOCK_REGISTRY)
    const allowPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[Allow]')) as Record<string, unknown>
    assert.ok(allowPolicy, '[Allow] policy missing')
    assert.equal(allowPolicy.action, 'Allow')
    // Allow policy has no profile_action and no traffic_action
    assert.equal(allowPolicy.profile_action, null)
    assert.ok(!('traffic_action' in allowPolicy), 'Allow policy must not have traffic_action')
    assert.ok(
      result.mapping_report.tests_required.some(t => t.toLowerCase().includes('allow')),
      'No allow scope warning in tests_required',
    )
  })

  test('label detection upload only — partial status, label in lossy_mappings', () => {
    const result = translate(FIXTURES.labelDetectionUploadOnly, MOCK_REGISTRY)
    assert.ok(result.mapping_report.lossy_mappings.some(m => m.toLowerCase().includes('label')), 'label lossy mapping missing')
    assert.equal(result.status, 'partial')
  })

  test('post prompt monitor — Post activity in destination', () => {
    const result = translate(FIXTURES.postPromptMonitor, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy)
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.ok((dest.activities as string[]).includes('Post'), 'Post activity missing for post_prompt monitor')
  })

  test('scope_all_apps: true — destination has category not specific_apps', () => {
    const result = translate(FIXTURES.scopeAllApps, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy)
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.ok(dest.category, 'category missing for scope_all_apps')
    assert.ok(!dest.specific_apps, 'specific_apps should not be present when scope_all_apps')
  })

  test('scope_app_ids specific — destination has specific_apps list', () => {
    const result = translate(FIXTURES.scopeSpecificApps, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy)
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.ok(Array.isArray(dest.specific_apps), 'specific_apps missing for scope_app_ids')
    assert.deepEqual(dest.specific_apps, ['chatgpt', 'claude', 'gemini'])
  })

  test('all policies have source, status, group, destination.activities, profile_action', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy.source, 'source missing')
    assert.equal(mainPolicy.status, 'enabled')
    assert.ok(typeof mainPolicy.group === 'string', 'group missing')
    // profile_action is an object (not array) or null
    assert.ok('profile_action' in mainPolicy, 'profile_action key must be present')
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.ok(Array.isArray(dest.activities), 'destination.activities missing')
  })

  test('no traffic_action emitted by default — it is not mandatory', () => {
    for (const fixture of Object.values(FIXTURES)) {
      const result = translate(fixture, MOCK_REGISTRY)
      for (const p of result.native_policies) {
        const policy = p as Record<string, unknown>
        assert.ok(!('traffic_action' in policy), `traffic_action must not be emitted by default (fixture policy: ${policy.name})`)
      }
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
