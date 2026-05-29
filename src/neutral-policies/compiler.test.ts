import { test, describe } from 'node:test'
import assert from 'node:assert/strict'
import { compileNeutralPoliciesForOrg } from './compiler'
import type {
  CompilerInput, GovernanceCategoryRow, ControlMatrixOverrideRow,
  ClassificationLabelRow, CustomerSensitivityLabelRow, CatalogDataTypeRow,
} from './compiler'

// ── Shared fixtures ───────────────────────────────────────────────────────────

const ALL_CATEGORIES: GovernanceCategoryRow[] = [
  { id: 'cat-ea',  system_tag: 'enterprise-approved',        name: 'Enterprise Approved',    active: true },
  { id: 'cat-awc', system_tag: 'approved-with-conditions',   name: 'Approved w/ Conditions', active: true },
  { id: 'cat-pwr', system_tag: 'permitted-with-restriction', name: 'Restricted',             active: true },
  { id: 'cat-pro', system_tag: 'prohibited',                 name: 'Prohibited',             active: true },
]

const CLASSIFICATION_LABELS: ClassificationLabelRow[] = [
  { id: 'lbl-secret', system_level: 'secret',              name: 'Secret',             active: true },
  { id: 'lbl-hc',     system_level: 'highly_confidential', name: 'Highly Confidential', active: true },
  { id: 'lbl-conf',   system_level: 'confidential',        name: 'Confidential',       active: true },
]

const IN_SCOPE_DATA_TYPES: CatalogDataTypeRow[] = [
  { slug: 'api-key',     name: 'API Key',            system_level: 'secret' },
  { slug: 'private-key', name: 'Private Key',        system_level: 'secret' },
  { slug: 'pii-email',   name: 'Email Address',      system_level: 'highly_confidential' },
  { slug: 'pci-pan',     name: 'Credit Card Number', system_level: 'highly_confidential' },
  { slug: 'ip-code',     name: 'Source Code',        system_level: 'confidential' },
]

const NO_OVERRIDES:       ControlMatrixOverrideRow[]     = []
const NO_CUSTOMER_LABELS: CustomerSensitivityLabelRow[]  = []

function makeInput(overrides: Partial<CompilerInput> = {}): CompilerInput {
  return {
    orgId:                    'org-test',
    governanceCategories:     ALL_CATEGORIES,
    controlMatrixOverrides:   NO_OVERRIDES,
    classificationLabels:     CLASSIFICATION_LABELS,
    customerSensitivityLabels: NO_CUSTOMER_LABELS,
    inScopeDataTypes:         IN_SCOPE_DATA_TYPES,
    onboardingProfile:        { tools: ['netskope'] },
    ...overrides,
  }
}

// ── Fixture 1: Secret credentials block ──────────────────────────────────────

describe('Fixture 1 — secret credentials block', () => {
  test('produces a block policy with post+upload activities and no download', () => {
    const outputs = compileNeutralPoliciesForOrg(makeInput())
    const secretBlock = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-content-secret-block',
    )
    assert.ok(secretBlock, 'secret-block policy not found')
    const npj = secretBlock.neutralPolicy

    assert.equal(npj.intent, 'prevent_exfiltration')
    assert.equal(npj.policy_family, 'GenAI Content Detection')
    assert.deepEqual(npj.scope.activities, ['post', 'upload'])
    assert.ok(!npj.scope.activities.includes('download'), 'download should not be in activities')
    assert.equal(npj.decision.mode, 'block')
    assert.equal(npj.decision.severity, 'critical')
    assert.equal(npj.decision.preserve_evidence, true)
    assert.equal(npj.decision.create_incident, true)
    assert.ok(npj.content.conditions.length > 0, 'no conditions')
    assert.ok(npj.content.conditions.every(c => c.type === 'data_type'), 'non-data_type condition')
    assert.ok(npj.content.conditions.every(c => c.sensitivity === 'secret'), 'wrong sensitivity')
    assert.ok(npj.scope.channels.includes('copilot'), 'copilot channel missing')
    assert.ok(npj.scope.channels.includes('chat'), 'chat channel missing')
  })
})

// ── Fixture 2: Confidential coach with acknowledgement ───────────────────────

describe('Fixture 2 — confidential coach-ack', () => {
  test('produces coach policy at confidential level', () => {
    const outputs = compileNeutralPoliciesForOrg(makeInput())
    const coachPolicies = outputs.filter(
      o => o.neutralPolicy.policy_family === 'GenAI Content Detection' &&
           o.neutralPolicy.decision.mode === 'coach' &&
           o.neutralPolicy.content.conditions.some(c => c.sensitivity === 'confidential'),
    )
    assert.ok(coachPolicies.length > 0, 'no coach policy at confidential level')
    const npj = coachPolicies[0].neutralPolicy
    assert.deepEqual(npj.scope.activities, ['post', 'upload'])
  })

  test('produces coach-ack policy when override forces coach-ack', () => {
    const overrides: ControlMatrixOverrideRow[] = [
      { data_type: 'pp|lbl-conf', category_id: 'cat-ea', action_code: 'coach-ack' },
    ]
    const outputs = compileNeutralPoliciesForOrg(makeInput({ controlMatrixOverrides: overrides }))
    const coachAck = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-content-confidential-coach-ack',
    )
    assert.ok(coachAck, 'coach-ack policy not found')
    assert.equal(coachAck.neutralPolicy.decision.require_acknowledgement, true)
    assert.equal(coachAck.neutralPolicy.decision.require_justification, false)
  })
})

// ── Fixture 3: Customer MIP label upload block ────────────────────────────────

describe('Fixture 3 — customer MIP label upload block', () => {
  test('produces a classification_label condition policy for upload only', () => {
    const mipLabel: CustomerSensitivityLabelRow = {
      id:           'clbl-mip-001',
      display_name: 'MIP Highly Confidential',
      label_key:    'MSIP_Label_abc123_Enabled',
      label_value:  'True',
      label_source: 'mip',
      system_level: 'highly_confidential',
      active:       true,
    }
    const outputs = compileNeutralPoliciesForOrg(
      makeInput({ customerSensitivityLabels: [mipLabel] })
    )
    const labelPolicy = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-label-detection-clbl-mip-001',
    )
    assert.ok(labelPolicy, 'label detection policy not found')
    const npj = labelPolicy.neutralPolicy

    assert.equal(npj.policy_family, 'GenAI Label Detection')
    assert.deepEqual(npj.scope.activities, ['upload'])
    assert.ok(!npj.scope.activities.includes('post'), 'post should not be in activities')
    assert.equal(npj.content.conditions.length, 1)

    const cond = npj.content.conditions[0]
    assert.equal(cond.type, 'classification_label')
    if (cond.type === 'classification_label') {
      assert.equal(cond.label_source, 'mip')
      assert.equal(cond.metadata_key, 'MSIP_Label_abc123_Enabled')
      assert.equal(cond.metadata_value, 'True')
    }
    assert.ok(!npj.scope.channels.includes('copilot'), 'copilot should not be in channels for label detection')
    assert.ok(!npj.scope.channels.includes('chat'), 'chat should not be in channels for label detection')
  })
})

// ── Fixture 4: Filename detection ─────────────────────────────────────────────

describe('Fixture 4 — filename detection', () => {
  test('produces filename conditions for secret with upload-only activities', () => {
    const outputs = compileNeutralPoliciesForOrg(makeInput())
    const secretFn = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-filename-detection-secret',
    )
    assert.ok(secretFn, 'filename detection policy for secret not found')
    const npj = secretFn.neutralPolicy

    assert.equal(npj.policy_family, 'GenAI Filename Detection')
    assert.deepEqual(npj.scope.activities, ['upload'])
    assert.equal(npj.content.conditions.length, 1)
    const cond = npj.content.conditions[0]
    assert.equal(cond.type, 'filename')
    if (cond.type === 'filename') {
      assert.ok(cond.pattern.includes('*secret*'), 'pattern missing *secret*')
      assert.ok(cond.pattern.includes('*password*'), 'pattern missing *password*')
    }
  })

  test('produces filename conditions for highly_confidential', () => {
    const outputs = compileNeutralPoliciesForOrg(makeInput())
    const hcFn = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-filename-detection-highly_confidential',
    )
    assert.ok(hcFn, 'filename detection policy for HC not found')
    const hcCond = hcFn.neutralPolicy.content.conditions[0]
    if (hcCond.type === 'filename') {
      assert.ok(hcCond.pattern.includes('*confidential*'), 'HC pattern missing *confidential*')
    }
  })
})

// ── Fixture 5: Prohibited app block ──────────────────────────────────────────

describe('Fixture 5 — prohibited app block', () => {
  test('produces an app-access block policy with empty content conditions', () => {
    const outputs = compileNeutralPoliciesForOrg(makeInput())
    const prohibitedPolicy = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-app-access-prohibited',
    )
    assert.ok(prohibitedPolicy, 'prohibited app policy not found')
    const npj = prohibitedPolicy.neutralPolicy

    assert.equal(npj.intent, 'govern_app_access')
    assert.equal(npj.decision.mode, 'block')
    assert.equal(npj.content.conditions.length, 0)
    assert.ok(npj.scope.activities.includes('browse'), 'browse missing from activities')
    assert.ok(npj.scope.activities.includes('download'), 'download missing from activities')
    assert.ok(!npj.scope.channels.includes('saas_api'), 'saas_api should not be in app-access channels')
    assert.equal(npj.scope.app_categories.length, 1)
    assert.equal(npj.scope.app_categories[0].system_tag, 'prohibited')
  })

  test('always generates prohibited block even without control matrix overrides', () => {
    const outputs = compileNeutralPoliciesForOrg(makeInput({ controlMatrixOverrides: [] }))
    const prohibitedPolicy = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-app-access-prohibited',
    )
    assert.ok(prohibitedPolicy, 'prohibited policy should always be generated')
  })
})

// ── Fixture 6: Approved use allow ────────────────────────────────────────────

describe('Fixture 6 — approved use allow', () => {
  test('produces an allow policy with scoping warnings', () => {
    const outputs = compileNeutralPoliciesForOrg(makeInput())
    const approvedPolicy = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-approved-use-enterprise',
    )
    assert.ok(approvedPolicy, 'approved-use policy not found')
    const npj = approvedPolicy.neutralPolicy

    assert.equal(npj.intent, 'allow_approved_use')
    assert.equal(npj.decision.mode, 'allow')
    assert.ok(npj.provenance.warnings.length > 0, 'no warnings on approved-use policy')
    assert.ok(
      npj.provenance.warnings.some(w => w.toLowerCase().includes('scope')),
      'no scope warning on approved-use policy',
    )
    assert.ok(npj.scope.channels.includes('copilot'), 'copilot missing from approved-use channels')
    assert.ok(npj.scope.channels.includes('saas_api'), 'saas_api missing from approved-use channels')
  })
})

// ── Restricted app access: conditional generation ────────────────────────────

describe('Restricted app access control', () => {
  test('does NOT generate restricted policy without a restrictive override', () => {
    const outputs = compileNeutralPoliciesForOrg(makeInput({ controlMatrixOverrides: [] }))
    const restricted = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-app-access-restricted',
    )
    assert.equal(restricted, undefined, 'restricted policy should not be generated without override')
  })

  test('DOES generate restricted policy when a restrictive override exists', () => {
    const overrides: ControlMatrixOverrideRow[] = [
      { data_type: 'pp|lbl-secret', category_id: 'cat-pwr', action_code: 'coach' },
    ]
    const outputs = compileNeutralPoliciesForOrg(makeInput({ controlMatrixOverrides: overrides }))
    const restricted = outputs.find(
      o => o.neutralPolicy.policy_key === 'genai-app-access-restricted',
    )
    assert.ok(restricted, 'restricted policy should be generated when restrictive override exists')
  })
})

// ── Hash stability ────────────────────────────────────────────────────────────

describe('Hash stability', () => {
  test('produces the same hash on two identical compilations', () => {
    const input = makeInput()
    const out1 = compileNeutralPoliciesForOrg(input)
    const out2 = compileNeutralPoliciesForOrg(input)
    for (const o1 of out1) {
      const o2 = out2.find(o => o.neutralPolicy.policy_key === o1.neutralPolicy.policy_key)
      assert.ok(o2, `policy ${o1.neutralPolicy.policy_key} missing from second run`)
      assert.equal(o1.hash, o2.hash, `hash mismatch for ${o1.neutralPolicy.policy_key}`)
    }
  })
})
