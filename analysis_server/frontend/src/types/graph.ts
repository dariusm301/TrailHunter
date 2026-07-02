export type RelationKind = 'requires/provides' | 'parent'

export interface NodeFields {
  timestamp: string 
  action: string
  severity: string
  kill_chain: string
  user: string
  process: string
  source_ip?: string | null
}

export interface GraphNode {
  id: string
  type?: string
  label: string
  actor?: number | null
  fields: {
    timestamp?: string
    rule?: string
    severity?: string
    kill_chain?: string
    user?: string
    process?: string
    events?: string
    source_ip?: string | null
    fused_signals?: string | null
    logon_id?: string | null
  }
  event_ids?: string[]
  requires?: { name?: string; bind?: string[]; values?: string[] }[]
  provides?: { name?: string; bind?: string[]; values?: string[] }[]
  fusion_key?: (string | number)[][]
  is_probe?: boolean
}

export interface GraphEdge {
  source: string
  target: string
  relation: RelationKind
  nature: string 
  cap: string | null 
}

export interface CorrelationGraph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  actor_count: number
  collector_ips?: string[] | null
}