import { useEffect, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, ApiError, type AnalysisMode, type Job } from '../api'

interface LogEvent {
  type: 'log' | 'status'
  level?: 'info' | 'warn' | 'error'
  message?: string
  status?: string
  [key: string]: unknown
}

const STEPS_BY_MODE: Record<AnalysisMode, readonly string[]> = {
  sast: ['AWAITING_MODE', 'QUEUED', 'PARSING', 'DONE'],
  sast_dast: ['AWAITING_MODE', 'QUEUED', 'PARSING', 'DEVICE_CHECK', 'MOBSF_DAST', 'DONE'],
  sast_dast_burp: [
    'AWAITING_MODE',
    'QUEUED',
    'PARSING',
    'DEVICE_CHECK',
    'MOBSF_DAST',
    'AWAITING_BURP_CONFIRM',
    'INSTALLING',
    'CA_TRUST',
    'PROXY_SET',
    'FRIDA_ATTACH',
    'STATIC_PATCH',
    'DONE',
  ],
}
const DEFAULT_STEPS = ['AWAITING_MODE', 'QUEUED', 'PARSING', 'DONE'] as const

const WS_RECONNECT_DELAY_MS = 2500
const WS_MAX_RECONNECT_ATTEMPTS = 8

export function JobDetail() {
  const { jobId } = useParams<{ jobId: string }>()
  const [job, setJob] = useState<Job | null>(null)
  const [jobError, setJobError] = useState<string | null>(null)
  const [events, setEvents] = useState<LogEvent[]>([])
  const [confirming, setConfirming] = useState(false)
  const [confirmError, setConfirmError] = useState<string | null>(null)
  const [reconnecting, setReconnecting] = useState(false)
  const logRef = useRef<HTMLDivElement>(null)

  function loadJob(id: string) {
    setJobError(null)
    api
      .getJob(id)
      .then(setJob)
      .catch((err: unknown) => {
        setJobError(err instanceof ApiError ? err.message : 'Failed to load job')
      })
  }

  useEffect(() => {
    if (!jobId) return
    loadJob(jobId)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId])

  useEffect(() => {
    if (!jobId) return
    // Narrow once, outside the nested `connect()`/`onmessage` closures below - TS's control-flow
    // narrowing from the guard above doesn't propagate into those nested function bodies, so
    // `jobId` itself stays typed `string | undefined` there even though it can't actually change.
    const currentJobId = jobId

    let socket: WebSocket | null = null
    let reconnectAttempts = 0
    let reconnectTimer: ReturnType<typeof setTimeout> | undefined
    let stopped = false

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws'
      socket = new WebSocket(`${protocol}://${window.location.host}/ws/jobs/${currentJobId}`)

      socket.onopen = () => {
        reconnectAttempts = 0
        setReconnecting(false)
      }

      socket.onmessage = (message) => {
        const event = JSON.parse(message.data) as LogEvent
        setEvents((prev) => [...prev, event])
        if (event.type === 'status') {
          loadJob(currentJobId)
        }
      }

      socket.onerror = () => {
        // onclose fires right after onerror for a failed/dropped connection;
        // the actual retry scheduling lives there so it only happens once.
      }

      socket.onclose = () => {
        if (stopped) return
        if (reconnectAttempts >= WS_MAX_RECONNECT_ATTEMPTS) {
          setReconnecting(false)
          return
        }
        reconnectAttempts += 1
        setReconnecting(true)
        reconnectTimer = setTimeout(connect, WS_RECONNECT_DELAY_MS)
      }
    }

    connect()

    return () => {
      stopped = true
      if (reconnectTimer) clearTimeout(reconnectTimer)
      socket?.close()
    }
  }, [jobId])

  useEffect(() => {
    logRef.current?.scrollTo({ top: logRef.current.scrollHeight })
  }, [events])

  async function handleConfirmBurp() {
    if (!jobId) return
    setConfirming(true)
    setConfirmError(null)
    try {
      await api.confirmBurp(jobId)
    } catch (err: unknown) {
      setConfirmError(err instanceof ApiError ? err.message : 'Could not confirm')
    } finally {
      setConfirming(false)
    }
  }

  if (!job) {
    if (jobError) {
      return (
        <div className="page">
          <Link to="/" className="back-link">
            &larr; Dashboard
          </Link>
          <div className="error-text">{jobError}</div>
          <button onClick={() => jobId && loadJob(jobId)}>Retry</button>
        </div>
      )
    }
    return <div className="page">Loading...</div>
  }

  const steps = job.analysis_mode ? STEPS_BY_MODE[job.analysis_mode] : DEFAULT_STEPS
  const currentStepIndex = steps.indexOf(job.status)

  return (
    <div className="page">
      <Link to="/" className="back-link">
        &larr; Dashboard
      </Link>
      <h2>{job.original_filename}</h2>
      <div className="job-meta">
        <span className={`status-pill status-${job.status.toLowerCase()}`}>{job.status}</span>
        {job.analysis_mode && <span className="analysis-tag">{job.analysis_mode}</span>}
        {job.device_target_type && (
          <span className="tag">
            target: {job.device_target_type === 'physical' ? job.device_target_ip ?? 'physical' : 'emulator'}
            {job.device_serial ? ` (${job.device_serial})` : ''}
          </span>
        )}
        {job.package_name && <span>{job.package_name}</span>}
        {job.is_split_apk && <span className="tag">split-APK</span>}
        {job.is_flutter && <span className="tag">Flutter</span>}
        {job.bypass_method && <span className="tag">bypass: {job.bypass_method}</span>}
      </div>

      {job.status !== 'FAILED' && (
        <div className="pipeline-steps">
          {steps.map((step, idx) => (
            <div
              key={step}
              className={`pipeline-step ${idx <= currentStepIndex ? 'done' : ''} ${
                idx === currentStepIndex ? 'current' : ''
              }`}
            >
              {step}
            </div>
          ))}
        </div>
      )}

      {job.status === 'AWAITING_BURP_CONFIRM' && (
        <div className="burp-confirm-banner">
          <p>
            &#9888; Starting this PT session will close Burp&apos;s currently open project - any
            unsaved work there will be lost. Burp will restart pointed at a fresh, dedicated
            project file for this job.
          </p>
          <button onClick={handleConfirmBurp} disabled={confirming}>
            {confirming ? 'Confirming...' : 'Confirm & continue'}
          </button>
          {confirmError && <div className="error-text">{confirmError}</div>}
        </div>
      )}

      {job.failure_reason && <div className="error-text">{job.failure_reason}</div>}

      {(job.mobsf_report_url || job.mobsf_dynamic_report_url) && (
        <div className="report-links">
          {job.mobsf_report_url && (
            <a href={job.mobsf_report_url} target="_blank" rel="noreferrer">
              View MobSF static report
            </a>
          )}
          {job.mobsf_dynamic_report_url && (
            <a href={job.mobsf_dynamic_report_url} target="_blank" rel="noreferrer">
              View MobSF dynamic report
            </a>
          )}
        </div>
      )}

      <h3>
        Live log
        {reconnecting && <span className="tag reconnecting-tag"> reconnecting...</span>}
      </h3>
      <div className="log-pane" ref={logRef}>
        {events.map((event, idx) => (
          <div key={idx} className={`log-line log-${event.type === 'log' ? event.level : 'status'}`}>
            {event.type === 'log' ? event.message : `-- status: ${event.status} --`}
          </div>
        ))}
      </div>
    </div>
  )
}
