export type JobStatus =
  | 'AWAITING_MODE'
  | 'QUEUED'
  | 'PARSING'
  | 'DEVICE_CHECK'
  | 'INSTALLING'
  | 'MOBSF_DAST'
  | 'CA_TRUST'
  | 'PROXY_SET'
  | 'FRIDA_ATTACH'
  | 'STATIC_PATCH'
  | 'AWAITING_BURP_CONFIRM'
  | 'DONE'
  | 'FAILED'

export type AnalysisMode = 'sast' | 'sast_dast' | 'sast_dast_burp'

export type DeviceTargetType = 'emulator' | 'physical' | 'genymotion'

export interface Job {
  id: string
  created_at: string
  updated_at: string
  original_filename: string
  stored_path: string
  package_name: string | null
  is_split_apk: boolean
  is_flutter: boolean
  analysis_mode: AnalysisMode | null
  status: JobStatus
  bypass_method: string | null
  failure_reason: string | null
  mobsf_report_url: string | null
  mobsf_dynamic_report_url: string | null
  device_serial: string | null
  device_target_type: DeviceTargetType | null
  device_target_ip: string | null
}

export interface DeviceCheckResult {
  ok: boolean
  serial?: string
  error?: string
}

export interface JobLogLine {
  id: number
  job_id: string
  timestamp: string
  level: 'info' | 'warn' | 'error'
  message: string
}

export interface DeviceStatus {
  mobile_pt_status: string
  burp_api: Record<string, unknown> | null
  burp_proxy_listening: boolean
}

class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const resp = await fetch(path, {
    credentials: 'include',
    headers: init?.body instanceof FormData ? undefined : { 'Content-Type': 'application/json' },
    ...init,
  })
  if (!resp.ok) {
    const text = await resp.text().catch(() => resp.statusText)
    throw new ApiError(text, resp.status)
  }
  if (resp.status === 204) return undefined as T
  return (await resp.json()) as T
}

function uploadJob(file: File, onProgress?: (percent: number) => void): Promise<Job> {
  const formData = new FormData()
  formData.append('file', file)

  return new Promise<Job>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', '/api/jobs')
    xhr.withCredentials = true
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) {
        onProgress(Math.round((e.loaded / e.total) * 100))
      }
    }
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(JSON.parse(xhr.responseText) as Job)
      } else {
        reject(new ApiError(xhr.responseText || xhr.statusText, xhr.status))
      }
    }
    xhr.onerror = () => reject(new ApiError('Network error', 0))
    xhr.send(formData)
  })
}

export const api = {
  login: (username: string, password: string) =>
    request<{ ok: boolean }>('/api/login', {
      method: 'POST',
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ ok: boolean }>('/api/logout', { method: 'POST' }),
  listJobs: () => request<Job[]>('/api/jobs'),
  getJob: (id: string) => request<Job>(`/api/jobs/${id}`),
  getJobLogs: (id: string) => request<JobLogLine[]>(`/api/jobs/${id}/logs`),
  uploadJob,
  startJob: (
    id: string,
    mode: AnalysisMode,
    deviceTarget?: { type: DeviceTargetType; ip: string | null },
  ) =>
    request<Job>(`/api/jobs/${id}/start`, {
      method: 'POST',
      body: JSON.stringify({
        mode,
        device_target_type: deviceTarget?.type ?? null,
        device_target_ip: deviceTarget?.ip ?? null,
      }),
    }),
  confirmBurp: (id: string) =>
    request<{ ok: boolean }>(`/api/jobs/${id}/confirm_burp`, { method: 'POST' }),
  deviceStatus: () => request<DeviceStatus>('/api/device/status'),
  startDevice: () => request<{ ok: boolean }>('/api/device/start', { method: 'POST' }),
  checkDevice: (targetType: DeviceTargetType, ip?: string) =>
    request<DeviceCheckResult>('/api/device/check', {
      method: 'POST',
      body: JSON.stringify({ target_type: targetType, ip: ip ?? null }),
    }),
}

export { ApiError }
