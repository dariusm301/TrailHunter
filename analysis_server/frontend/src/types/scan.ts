export interface ScanSummary {
  id: string
  host: string
  collected_at: string 
  event_count: number
  finding_count: number | null 
  actor_count: number | null
  max_severity: string | null
  has_collector: boolean
}