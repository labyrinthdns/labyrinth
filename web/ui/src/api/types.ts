export interface LoginRequest {
  username: string
  password: string
}

export interface LoginResponse {
  token: string
}

export interface AuthUser {
  username: string
}

export interface StatsResponse {
  queries_by_type: Record<string, number>
  responses_by_rcode: Record<string, number>
  cache_hits: number
  cache_misses: number
  cache_evictions: number
  upstream_queries: number
  upstream_errors: number
  rate_limited: number
  uptime_seconds: number
  goroutines: number
  query_duration_count: number
  cache_entries: number
  cache_positive: number
  cache_negative: number
  cache_hit_ratio: number
  resolver_ready: boolean
}

export interface TimeSeriesBucket {
  ts: string
  queries: number
  cache_hits: number
  cache_misses: number
  errors: number
  avg_latency_ms: number
}

export interface QueryEntry {
  id: number
  ts: string
  client: string
  qname: string
  qtype: string
  rcode: string
  cached: boolean
  duration_ms: number
}

export interface CacheStats {
  entries: number
  positive_entries: number
  negative_entries: number
}

export interface CacheRecord {
  name: string
  type: string
  ttl: number
  rdata: string
}

export interface CacheEntry {
  name: string
  type: string
  ttl: number
  negative: boolean
  records: CacheRecord[]
}

export interface SetupStatus {
  setup_required: boolean
  version: string
  os_arch: string
}

export interface SetupRequest {
  admin_username: string
  admin_password: string
  listen_addr: string
  metrics_addr: string
  cache_max_entries: number
  qname_minimization: boolean
  rate_limit_enabled: boolean
  rate_limit_rate: number
  rate_limit_burst: number
  log_level: string
  log_format: string
}

export interface HealthResponse {
  status: string
  cache_entries: number
  uptime: string
  resolver_ready: boolean
}

export interface VersionResponse {
  version: string
  build_time: string
  go_version: string
  os_arch: string
}
