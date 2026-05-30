export interface ActivityEntry {
  activity_key:            string
  vendor_activity_name:    string
  display_name:            string
  description:             string
  execution_modes:         string[]
  support_level:           'supported' | 'partially_supported' | 'app_specific' | 'not_publicly_verified'
  policy_selectable:       string
  event_emission_behavior: string
  requires_dlp:            boolean | 'context_dependent'
  supported_for_genai:     string
  limitations:             string[]
  verification_status:     string
}

export interface ActionEntry {
  action_key:                string
  vendor_action_name:        string
  display_name:              string
  description:               string
  execution_modes:           string[]
  supported_policy_types:    string[]
  user_interaction:          boolean | string
  creates_alert:             boolean | string
  creates_incident:          boolean | string
  supports_evidence_capture: boolean | string
  dependencies:              string[]
  limitations:               string[]
  verification_status:       string
}

export interface LimitationEntry {
  limitation_key:      string
  title:               string
  description:         string
  impact:              string
  affected_objects:    string[]
  recommended_warning: string
  validation_method:   string
  severity:            'critical' | 'high' | 'medium'
  verification_status: string
}

export interface PrerequisiteEntry {
  requirement_key:                string
  title:                          string
  description:                    string
  applies_to:                     string[]
  why_it_matters:                 string
  validation_method:              string
  blocks_verification_if_missing: boolean | string
  severity:                       'critical' | 'high' | 'medium'
}

export interface TestRequirementEntry {
  test_key:            string
  title:               string
  applies_to:          string[]
  severity:            'critical' | 'high' | 'medium'
  test_step:           string
  expected_result:     string
  evidence_to_capture: string[]
}

export interface VendorCatalog {
  schema_version:  string
  vendor_catalog: {
    vendor_id:        string
    catalog_version:  string
    status:           string
    last_verified_at: string
    next_review_due:  string
  }
  activities:        ActivityEntry[]
  actions:           ActionEntry[]
  limitations:       LimitationEntry[]
  prerequisites:     PrerequisiteEntry[]
  test_requirements: TestRequirementEntry[]
}
