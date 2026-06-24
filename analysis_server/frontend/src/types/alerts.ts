export interface DetectionFinding {
  id: string
  timestamp: string | null
  rule_id: string
  rule_name: string
  rule_type: string
  severity: string
  confidence: number
  kill_chain_phase: string | null
  tactic: string | null
  technique_id: string | null
  technique_name: string | null
  source: string
  description: string
  tags: string[]
  event_count: number
  entities: Record<string, unknown>
  is_probe: boolean
}

export interface DetectResult {
  status: string
  total_findings: number
  max_severity: string
  findings: DetectionFinding[]
  error?: string
}