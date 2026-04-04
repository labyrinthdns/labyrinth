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
  dnssec_secure: number
  dnssec_insecure: number
  dnssec_bogus: number
  blocked_queries: number
}

export interface TimeSeriesBucket {
  ts?: string
  timestamp?: string
  queries: number
  cache_hits: number
  cache_misses: number
  errors: number
  avg_latency_ms: number
}

export interface SystemProfileResponse {
  hostname: string
  network: {
    ip_addresses: string[]
    interfaces: {
      name: string
      mtu: number
      hardware_addr?: string
      flags?: string[]
      addrs?: string[]
    }[]
    io: {
      rx_bytes_total: number
      tx_bytes_total: number
      rx_packets_total: number
      tx_packets_total: number
    }
  }
  runtime: {
    version: string
    build_time: string
    go_version: string
    os: string
    arch: string
    cpu_cores: number
    go_maxprocs: number
    goroutines: number
  }
  cpu: {
    process_cpu_seconds_total: number
    load_avg_1m: number
    load_avg_5m: number
    load_avg_15m: number
  }
  memory: {
    process_alloc_bytes: number
    process_heap_bytes: number
    process_sys_bytes: number
    system_total_bytes: number
    system_free_bytes: number
    gc_cycles: number
  }
  disk: {
    path: string
    total_bytes: number
    free_bytes: number
    used_bytes: number
    used_pct: number
  }
  traffic: {
    dns_queries_total: number
    upstream_queries_total: number
    blocked_queries_total: number
    rate_limited_total: number
    last_minute_qps_avg: number
    last_minute_qps_peak: number
    last_minute_error_total: number
  }
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
  global_num: number
  client_num: number
  blocked?: boolean
  dnssec_status?: string
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

export interface TopEntry {
  key: string
  count: number
}

export interface NegativeCacheEntry {
  name: string
  type: string
  neg_type: string
  rcode: string
  ttl: number
  authority: { name: string; type: string; ttl: number; rdata: string }[]
}

export interface UpdateInfo {
  current_version: string
  latest_version: string
  update_available: boolean
  release_url?: string
  release_notes?: string
  asset_name?: string
}

export interface BlocklistStats {
  enabled: boolean
  total_rules: number
  list_count: number
  blocked_total: number
  custom_blocks: number
  custom_allows: number
  blocking_mode: string
}

export interface BlocklistListEntry {
  url: string
  format: string
  enabled: boolean
  last_update: string
  rule_count: number
  error?: string
}

export interface ConfigRawResponse {
  path: string
  content: string
}

export interface ConfigValidateResponse {
  valid: boolean
  error?: string
}

export interface ConfigSaveResponse {
  status: string
  path: string
  restart_required: boolean
}
