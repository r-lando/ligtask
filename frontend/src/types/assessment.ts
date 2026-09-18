export type InputType = 'ZIP' | 'GITHUB'

export type AssessmentStatus =
  | 'completed'
  | 'partial'
  | 'processing'
  | 'failed'

export type FindingSeverity =
  | 'CRITICAL'
  | 'HIGH'
  | 'MEDIUM'
  | 'LOW'
  | 'INFO'
  | 'UNKNOWN'

export type FindingCategory =
  | 'SAST'
  | 'DEPENDENCY'
  | 'SECRET'
  | 'CONFIGURATION'
  | string

export interface SeveritySummary {
  CRITICAL: number
  HIGH: number
  MEDIUM: number
  LOW: number
  INFO: number
  UNKNOWN: number
}

export interface RepositoryProfile {
  total_files: number
  languages: Record<string, number>
  dependency_files: string[]
  configuration_files: string[]
}

export interface AssessmentHistoryItem {
  assessment_id: string
  repository_name: string
  input_type: InputType
  status: AssessmentStatus
  created_at: string
  completed_at: string | null
  uploaded_size_bytes: number
  extracted_size_bytes: number
  total_files: number
  processing_time_ms: number
  raw_findings_count: number
  consolidated_findings_count: number
  severity_summary: SeveritySummary
  correlated_groups: number
  duplicate_findings_merged: number
  repository_profile: RepositoryProfile
}

export interface AssessmentHistoryResponse {
  total: number
  limit: number
  offset: number
  assessments: AssessmentHistoryItem[]
}

export interface AssessmentFinding {
  id: number
  scanner: string
  category: FindingCategory
  rule_id: string
  title: string
  severity: FindingSeverity

  cvss_score: number | null
  cvss_vector: string | null
  cvss_version: string | null

  file: string
  line: number | null

  message: string

  package: string | null
  version: string | null
  ecosystem: string | null

  correlated: boolean
  evidence_count: number
  sources: string[]
  source_rule_ids: string[]

  description: string
  recommendation: string
  guidance_source: string
}

export interface AssessmentDetail
  extends AssessmentHistoryItem {
  findings: AssessmentFinding[]
}