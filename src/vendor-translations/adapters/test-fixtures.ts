import type { NeutralPolicy, VendorCapabilityRegistry } from '../types'

export const MOCK_REGISTRY: VendorCapabilityRegistry = {
  vendor_id: 'test',
  version:   '2025-01',
  features:  { policy_split_required: false },
}

export const FIXTURES: Record<string, NeutralPolicy> = {
  secretUploadBlock: {
    id: 'p1', name: 'Block Secret Uploads', description: null,
    policy_type: 'data-handling', policy_family: 'GenAI Content Detection',
    primary_action: 'block', data_classification_label: 'secret',
    scope_all_apps: true, scope_app_ids: [],
    rules: [
      { data_type: 'secret', post_prompt: 'block', upload: 'block', download: 'monitor', response: 'not-set' },
    ],
  },

  confidentialCoach: {
    id: 'p2', name: 'Coach Confidential', description: null,
    policy_type: 'data-handling', policy_family: 'GenAI Content Detection',
    primary_action: 'coach', data_classification_label: 'confidential',
    scope_all_apps: true, scope_app_ids: [],
    rules: [
      { data_type: 'confidential', post_prompt: 'coach', upload: 'coach', download: 'monitor', response: 'not-set' },
    ],
  },

  approvedUseAllow: {
    id: 'p3', name: 'Approved Apps Allow', description: null,
    policy_type: 'approved-use', policy_family: 'GenAI Approved Usage',
    primary_action: 'allow', data_classification_label: null,
    scope_all_apps: false, scope_app_ids: ['app-copilot', 'app-gemini'],
    rules: [
      { data_type: 'all', post_prompt: 'allow', upload: 'allow', download: 'allow', response: 'not-set' },
    ],
  },

  labelDetectionUploadOnly: {
    id: 'p4', name: 'Label Detection Upload', description: null,
    policy_type: 'data-handling', policy_family: 'GenAI Label Detection',
    primary_action: 'block', data_classification_label: 'highly-confidential',
    scope_all_apps: true, scope_app_ids: [],
    rules: [
      { data_type: 'clabel:abc-123', post_prompt: 'not-set', upload: 'block', download: 'monitor', response: 'not-set' },
    ],
  },

  postPromptMonitor: {
    id: 'p5', name: 'Monitor AI Prompts', description: null,
    policy_type: 'usage', policy_family: 'GenAI Monitoring',
    primary_action: 'monitor', data_classification_label: 'all',
    scope_all_apps: true, scope_app_ids: [],
    rules: [
      { data_type: 'all', post_prompt: 'monitor', upload: 'monitor', download: 'not-set', response: 'not-set' },
    ],
  },

  scopeAllApps: {
    id: 'p6', name: 'All Apps Policy', description: null,
    policy_type: 'data-handling', policy_family: 'GenAI Content Detection',
    primary_action: 'alert', data_classification_label: 'internal',
    scope_all_apps: true, scope_app_ids: [],
    rules: [
      { data_type: 'internal', post_prompt: 'alert', upload: 'alert', download: 'monitor', response: 'not-set' },
    ],
  },

  scopeSpecificApps: {
    id: 'p7', name: 'Specific Apps Policy', description: null,
    policy_type: 'data-handling', policy_family: 'GenAI Content Detection',
    primary_action: 'block', data_classification_label: 'highly-confidential',
    scope_all_apps: false, scope_app_ids: ['chatgpt', 'claude', 'gemini'],
    rules: [
      { data_type: 'highly-confidential', post_prompt: 'block', upload: 'block', download: 'alert', response: 'not-set' },
    ],
  },
}
