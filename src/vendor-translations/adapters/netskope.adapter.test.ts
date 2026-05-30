import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { translate } from './netskope.adapter'
import { FIXTURES, MOCK_REGISTRY } from './test-fixtures'
import type { OrgVendorObjectMapping, NeutralPolicy } from '../types'

// ── Helpers for customer-mapping tests ────────────────────────────────────────

function makeMapping(overrides: Partial<OrgVendorObjectMapping> = {}): OrgVendorObjectMapping {
  return {
    id: 'm1', org_id: 'org1', vendor_id: 'netskope',
    neutral_object_type: 'app_category',
    neutral_object_key:  'genai-productivity',
    neutral_object_display_name: null,
    vendor_object_type:  'custom_category',
    vendor_object_key:   null,
    vendor_object_name:  'MyGenAIApps',
    vendor_object_id:    null,
    vendor_console_path: null,
    mapping_purpose:     'destination_scope',
    mapping_quality:     'exact',
    verification_status: 'verified',
    is_active:           true,
    not_applicable:      false,
    not_applicable_reason: null,
    verified:            true,
    verified_by:         'user1',
    verified_at:         '2026-01-01T00:00:00Z',
    verification_note:   null,
    updated_at:          '2026-01-01T00:00:00Z',
    metadata:            {},
    ...overrides,
  }
}

// Base NPJ — adapt per test by spreading specific fields into the nested objects
function makeNpjPolicy(options: {
  id?:           string
  name?:         string
  policy_type?:  string
  intent?:       'prevent_exfiltration' | 'detect_only' | 'coach_user' | 'allow_approved_use' | 'govern_app_access'
  activities?:   ('browse' | 'upload' | 'download' | 'post' | 'prompt_submit')[]
  app_categories?: Array<{ id: string; system_tag: string | null; name: string }>
  conditions?:   unknown[]
  decision_mode?: 'block' | 'allow' | 'monitor' | 'alert' | 'coach'
} = {}): NeutralPolicy {
  const {
    id = 'npj-test', name = 'NPJ Test', policy_type = 'data-handling',
    intent = 'prevent_exfiltration', activities = ['upload'],
    app_categories = [], conditions = [], decision_mode = 'block',
  } = options

  return {
    id, name, description: null, policy_type,
    policy_family: 'GenAI Content Detection',
    primary_action: decision_mode,
    data_classification_label: null,
    scope_all_apps: false, scope_app_ids: [],
    rules: [],
    neutral_policy_json: {
      schema_version: '1.0',
      id, name, description: 'Test',
      intent,
      policy_family: 'GenAI Content Detection',
      policy_key: 'test-key',
      scope: {
        users: [], groups: [], devices: [], device_posture: [],
        apps: [], app_categories, app_instances: [],
        channels: ['web'], activities,
      },
      content: { operator: 'any', conditions: conditions as never[] },
      decision: {
        mode: decision_mode, severity: 'critical',
        require_acknowledgement: false, require_justification: false,
        notification_template: null, preserve_evidence: false, create_incident: true,
      },
      exceptions: [],
      telemetry: { incident_recipients: [], export_evidence: false, audit_tags: [] },
      provenance: {
        generated_from: 'governance-matrix', source_cells: [],
        compiler_version: '1.0.0', generated_at: '2026-01-01T00:00:00Z', warnings: [],
      },
    },
  }
}

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

  test('all DLP policies have source, status, group, destination.activities, profile_action, action', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy.source, 'source missing')
    assert.equal(mainPolicy.status, 'enabled')
    assert.ok(typeof mainPolicy.group === 'string', 'group missing')
    assert.ok('profile_action' in mainPolicy, 'profile_action key must be present')
    // action must always be present even when profile_action is null
    assert.ok(typeof mainPolicy.action === 'string', 'action must always be present on DLP policy')
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.ok(Array.isArray(dest.activities), 'destination.activities missing')
  })

  test('rules data_type prefixes infer DLP profile names when no data_classification_label', () => {
    // Build a fixture with no label but rules with typed data_types
    const noLabelPolicy = {
      ...FIXTURES.secretUploadBlock,
      id: 'p-nolabel',
      data_classification_label: null,
      rules: [
        { data_type: 'secret:api-key', post_prompt: 'block', upload: 'block', download: 'not-set', response: 'not-set' },
        { data_type: 'secret:aws-key', post_prompt: 'block', upload: 'block', download: 'not-set', response: 'not-set' },
      ],
    }
    const result = translate(noLabelPolicy, MOCK_REGISTRY)
    const mainPolicy = result.native_policies.find((p: unknown) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    const profileAction = mainPolicy.profile_action as Record<string, unknown> | null
    // "secret:api-key" and "secret:aws-key" both prefix to "secret" → EFFATA-SECRET (deduplicated)
    assert.ok(profileAction !== null, 'profile_action must be set when rules have typed data_types')
    assert.deepEqual((profileAction!.dlp_profiles as string[]), ['EFFATA-SECRET'])
    assert.ok(result.mapping_report.lossy_mappings.some(m => m.includes('inferred from rule data_types')))
    // action must still be present
    assert.equal(mainPolicy.action, 'Block')
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
      assert.ok(Array.isArray(result.mapping_report.customer_mapping_required))
    }
  })
})

describe('netskope adapter — customer mappings', () => {
  // 1. App category mapping exists + verified → destination uses mapped name, exact quality
  test('verified app_category mapping → destination uses mapped name, exact in mapping_report', () => {
    const mapping = makeMapping({
      neutral_object_type: 'app_category',
      neutral_object_key:  'genai-productivity',
      vendor_object_name:  'MyGenAIApps',
      mapping_quality:     'exact',
      verification_status: 'verified',
      verified:            true,
    })
    const policy = makeNpjPolicy({
      app_categories: [{ id: 'cat1', system_tag: 'genai-productivity', name: 'GenAI Productivity' }],
    })
    const result = translate(policy, MOCK_REGISTRY, [mapping])
    const mainPolicy = result.native_policies.find((p) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.equal(dest.category, 'MyGenAIApps')
    assert.ok(result.mapping_report.exact_mappings.some(m => m.includes('MyGenAIApps')), 'exact_mappings should reference mapped name')
    assert.equal(result.mapping_report.customer_mapping_required.length, 0)
  })

  // 2. App category mapping missing → customer_mapping_required has entry, placeholder in destination, status partial
  test('missing app_category mapping → placeholder in destination, customer_mapping_required entry, status partial', () => {
    const policy = makeNpjPolicy({
      app_categories: [{ id: 'cat2', system_tag: 'uncharted-category', name: 'Unknown App Category' }],
    })
    const result = translate(policy, MOCK_REGISTRY, [])
    const mainPolicy = result.native_policies.find((p) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    const dest = mainPolicy.destination as Record<string, unknown>
    const cat = (dest.category ?? '') as string
    assert.ok(cat.includes('PLACEHOLDER'), `destination should be placeholder, got: ${cat}`)
    assert.ok(result.mapping_report.customer_mapping_required.length > 0, 'customer_mapping_required should have entry')
    assert.ok(
      (mainPolicy as Record<string, unknown>)._deployment_ready === false,
      '_deployment_ready should be false',
    )
    assert.equal(result.status, 'partial')
  })

  // 3. App access block + missing destination mapping → status deferred
  test('govern_app_access block + missing destination mapping → status deferred', () => {
    const policy = makeNpjPolicy({
      policy_type:    'app_access',
      intent:         'govern_app_access',
      activities:     ['browse'],
      decision_mode:  'block',
      app_categories: [{ id: 'cat3', system_tag: 'blocked-genai', name: 'Blocked GenAI' }],
    })
    const result = translate(policy, MOCK_REGISTRY, [])
    assert.equal(result.status, 'deferred')
    assert.ok(result.mapping_report.customer_mapping_required.length > 0)
  })

  // 4. Sensitivity DLP profile mapping exists → DLP profile uses mapped name
  test('verified sensitivity_level mapping → DLP profile uses mapped name', () => {
    const dlpMapping = makeMapping({
      neutral_object_type: 'sensitivity_level',
      neutral_object_key:  'secret',
      vendor_object_name:  'Tenant-Secret-Profile',
      mapping_quality:     'exact',
      verification_status: 'verified',
      verified:            true,
    })
    const policy = makeNpjPolicy({
      conditions: [{
        type: 'data_type', effata_data_type: 'secret',
        name: 'Secret Data', sensitivity: 'secret', confidence: 'high',
      }],
    })
    const result = translate(policy, MOCK_REGISTRY, [dlpMapping])
    const mainPolicy = result.native_policies.find((p) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    const profileAction = mainPolicy.profile_action as Record<string, unknown> | null
    assert.ok(profileAction, 'profile_action must be set')
    assert.ok(
      (profileAction!.dlp_profiles as string[]).includes('Tenant-Secret-Profile'),
      'DLP profile should use mapped name',
    )
    assert.ok(result.mapping_report.exact_mappings.some(m => m.includes('Tenant-Secret-Profile')))
    assert.equal(result.mapping_report.customer_mapping_required.length, 0)
  })

  // 5. Sensitivity DLP profile missing → customer_mapping_required, placeholder profile name
  test('missing sensitivity_level mapping → customer_mapping_required, placeholder DLP profile name', () => {
    const policy = makeNpjPolicy({
      conditions: [{
        type: 'data_type', effata_data_type: 'confidential',
        name: 'Confidential Data', sensitivity: 'confidential', confidence: 'medium',
      }],
    })
    const result = translate(policy, MOCK_REGISTRY, [])
    const mainPolicy = result.native_policies.find((p) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    const profileAction = mainPolicy.profile_action as Record<string, unknown> | null
    assert.ok(profileAction, 'profile_action must be set')
    const profiles = profileAction!.dlp_profiles as string[]
    assert.ok(profiles.some(p => p.startsWith('EFFATA-')), `DLP profile should be placeholder EFFATA-*, got: ${profiles}`)
    assert.ok(result.mapping_report.customer_mapping_required.length > 0)
  })

  // 6. Notification template mapping exists → template name used
  test('verified notification_template mapping → template name used for coach policy', () => {
    const dlpMapping = makeMapping({
      neutral_object_type: 'sensitivity_level',
      neutral_object_key:  'confidential',
      vendor_object_name:  'Tenant-Confidential-Profile',
      mapping_quality:     'exact',
      verification_status: 'verified',
      verified:            true,
    })
    const tplMapping = makeMapping({
      id:                  'm2',
      neutral_object_type: 'notification_template',
      neutral_object_key:  'default-coach',
      vendor_object_name:  'Tenant-Coach-Template',
      mapping_quality:     'exact',
      verification_status: 'verified',
      verified:            true,
    })
    const policy = makeNpjPolicy({
      decision_mode: 'coach',
      conditions: [{
        type: 'data_type', effata_data_type: 'confidential',
        name: 'Confidential Data', sensitivity: 'confidential', confidence: 'medium',
      }],
    })
    const result = translate(policy, MOCK_REGISTRY, [dlpMapping, tplMapping])
    const mainPolicy = result.native_policies.find((p) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    const profileAction = mainPolicy.profile_action as Record<string, unknown> | null
    assert.ok(profileAction, 'profile_action must be set when DLP conditions exist')
    assert.equal(profileAction!.notification_template, 'Tenant-Coach-Template')
    assert.ok(result.mapping_report.exact_mappings.some(m => m.includes('Tenant-Coach-Template')))
    assert.equal(result.mapping_report.customer_mapping_required.length, 0)
  })

  // 7. Notification template missing → customer_mapping_required, fallback placeholder name
  test('missing notification_template mapping → customer_mapping_required, placeholder template', () => {
    const dlpMapping = makeMapping({
      neutral_object_type: 'sensitivity_level',
      neutral_object_key:  'secret',
      vendor_object_name:  'Tenant-Secret-Profile',
      mapping_quality:     'exact',
      verification_status: 'verified',
      verified:            true,
    })
    const policy = makeNpjPolicy({
      decision_mode: 'coach',
      conditions: [{
        type: 'data_type', effata_data_type: 'secret',
        name: 'Secret Data', sensitivity: 'secret', confidence: 'high',
      }],
    })
    const result = translate(policy, MOCK_REGISTRY, [dlpMapping])
    const mainPolicy = result.native_policies.find((p) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    const profileAction = mainPolicy.profile_action as Record<string, unknown> | null
    assert.ok(profileAction, 'profile_action must be set when DLP conditions exist')
    assert.equal(profileAction!.notification_template, 'EFFATA-COACH-NOTIFICATION')
    assert.ok(result.mapping_report.customer_mapping_required.some(m => m.includes('default-coach')))
  })

  // 8. not_applicable mapping → no gap reported, excluded from customer_mapping_required
  test('not_applicable mapping → no gap in customer_mapping_required', () => {
    const naMapping = makeMapping({
      neutral_object_type: 'app_category',
      neutral_object_key:  'genai-productivity',
      not_applicable:      true,
      vendor_object_name:  'N/A',
    })
    const policy = makeNpjPolicy({
      app_categories: [{ id: 'cat4', system_tag: 'genai-productivity', name: 'GenAI Productivity' }],
    })
    const result = translate(policy, MOCK_REGISTRY, [naMapping])
    // not_applicable → skip without reporting a gap
    assert.equal(result.mapping_report.customer_mapping_required.length, 0)
    const mainPolicy = result.native_policies.find((p) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    assert.ok(mainPolicy._deployment_ready !== false, '_deployment_ready should not be false for not_applicable')
  })

  // 9. Lossy mapping (verified=true) stays lossy quality — not promoted to exact
  test('lossy mapping stays lossy even when verified=true — not promoted to exact', () => {
    const lossyMapping = makeMapping({
      neutral_object_type: 'app_category',
      neutral_object_key:  'genai-productivity',
      vendor_object_name:  'ApproxGenAICategory',
      mapping_quality:     'lossy',
      verification_status: 'verified',
      verified:            true,
      verification_note:   'Covers ~80% of GenAI apps',
    })
    const policy = makeNpjPolicy({
      app_categories: [{ id: 'cat5', system_tag: 'genai-productivity', name: 'GenAI Productivity' }],
    })
    const result = translate(policy, MOCK_REGISTRY, [lossyMapping])
    // lossy mapping → destination uses mapped name but quality stays lossy
    const mainPolicy = result.native_policies.find((p) => (p as Record<string, string>).name?.startsWith('[DLP]')) as Record<string, unknown>
    const dest = mainPolicy.destination as Record<string, unknown>
    assert.equal(dest.category, 'ApproxGenAICategory')
    // lossy → in lossy_mappings, NOT in exact_mappings
    assert.ok(result.mapping_report.lossy_mappings.some(m => m.includes('ApproxGenAICategory')))
    assert.ok(!result.mapping_report.exact_mappings.some(m => m.includes('ApproxGenAICategory')))
    // customer_mapping_required should be empty — mapping IS found
    assert.equal(result.mapping_report.customer_mapping_required.length, 0)
  })

  // 10. catalog_version + customer_mapping_version always present in result
  test('catalog_version and customer_mapping_version always present in result', () => {
    const result = translate(FIXTURES.secretUploadBlock, MOCK_REGISTRY, [])
    assert.ok(typeof result.catalog_version === 'string', 'catalog_version must be a string')
    assert.ok(result.catalog_version.length > 0, 'catalog_version must be non-empty')
    assert.ok(typeof result.customer_mapping_version === 'string', 'customer_mapping_version must be a string')
    // adapter returns '' — translateForVendor sets the real value from customerMappingVersion param
    assert.equal(result.customer_mapping_version, '')
  })

  // 11. All adapters accept third mappings param and include customer_mapping_required in report
  test('all adapters accept OrgVendorObjectMapping[] param and include customer_mapping_required', async () => {
    const { translate: purviewTranslate }     = await import('./purview.adapter')
    const { translate: forcepointTranslate }  = await import('./forcepoint.adapter')
    const { translate: skyhighTranslate }     = await import('./skyhigh.adapter')

    const basePolicy = FIXTURES.secretUploadBlock

    for (const [name, fn] of [
      ['purview', purviewTranslate],
      ['forcepoint', forcepointTranslate],
      ['skyhigh', skyhighTranslate],
    ] as const) {
      const result = fn(basePolicy, MOCK_REGISTRY, [])
      assert.ok(typeof result.customer_mapping_version === 'string', `${name}: customer_mapping_version missing`)
      assert.ok(Array.isArray(result.mapping_report.customer_mapping_required), `${name}: customer_mapping_required missing`)
      assert.equal(result.mapping_report.customer_mapping_required.length, 0, `${name}: stub should have no customer_mapping_required entries`)
    }
  })
})
