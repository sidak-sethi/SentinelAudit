export type Finding = {
  threat_id: string
  title: string
  cve: string | null
  attack_type: string
  severity: string
  source: { type: string; url: string; published?: string | null; retrieved_at?: string | null }
  status: string
  patch_status: string | null
  repository: string
  branch: string | null
  affected_files: string[]
  affected_lines: number[]
  confidence: number | null
  vulnerability_hypothesis: string
  recommended_fix: string
  security_test_path: string | null
  code: Record<string, { before: string; after: string | null }>
  diff: string | null
  patch_attempts: number
  final_audit: string | { status?: string; reasoning?: string; remaining_risk?: string[]; recommendation?: string } | null
  reason: string | null
  timestamp: string
  patch_available?: boolean
}

export type BackendHealth = {
  guard: string
  gemma_model_tag: string
  ollama_reachable: boolean
  model_pulled: boolean
}

export type BackendEvent = {
  timestamp: string
  component: string
  event: string
  status: string
  details: string
}

type ApiErrorBody = { error?: string; message?: string; status?: string; [key: string]: unknown }

export class ApiError extends Error {
  status: number
  body: ApiErrorBody

  constructor(status: number, body: ApiErrorBody) {
    super(body.error || body.message || `Backend returned ${status}`)
    this.status = status
    this.body = body
  }
}

const API_BASE = (import.meta.env.VITE_API_URL || '/api').replace(/\/$/, '')

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { ...(init?.body ? { 'Content-Type': 'application/json' } : {}), ...init?.headers },
    })
  } catch {
    throw new Error('Cannot reach the SentinelAudit backend. Start it with `python api_server.py`.')
  }
  const body = await response.json().catch(() => ({})) as ApiErrorBody
  if (!response.ok) throw new ApiError(response.status, body)
  return body as T
}

export const api = {
  health: () => request<BackendHealth>('/health'),
  findings: () => request<Finding[]>('/findings'),
  patchHistory: () => request<Finding[]>('/patch-history'),
  events: async () => {
    const [guard, offline] = await Promise.all([
      request<BackendEvent[]>('/events/guard'),
      request<BackendEvent[]>('/events/offline'),
    ])
    return [...guard, ...offline].sort((a, b) => b.timestamp.localeCompare(a.timestamp)).slice(0, 12)
  },
  scan: (repositoryUrl: string) => request<{ repository: string; repository_url: string; cloned: boolean; findings: Finding[] }>('/scan', {
    method: 'POST', body: JSON.stringify({ repository_url: repositoryUrl }),
  }),
  fix: (finding: Pick<Finding, 'threat_id' | 'repository'>) => request<Finding>(`/fixes/${encodeURIComponent(finding.threat_id)}`, {
    method: 'POST', body: JSON.stringify({ repository: finding.repository }),
  }),
}
