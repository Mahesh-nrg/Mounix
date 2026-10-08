import { useCallback, useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, type DeviceStatus, type Job } from '../api'

export function Dashboard() {
  const navigate = useNavigate()
  const [status, setStatus] = useState<DeviceStatus | null>(null)
  const [jobs, setJobs] = useState<Job[]>([])

  const refresh = useCallback(async () => {
    const [statusResult, jobsResult] = await Promise.all([api.deviceStatus(), api.listJobs()])
    setStatus(statusResult)
    setJobs(jobsResult)
  }, [])

  useEffect(() => {
    refresh().catch(() => undefined)
    const interval = setInterval(() => refresh().catch(() => undefined), 15000)
    return () => clearInterval(interval)
  }, [refresh])

  const emulatorUp = status?.mobile_pt_status.includes('device') ?? false

  return (
    <div className="page">
      <div className="hero">
        <h1>Mobile PT Lab</h1>
        <p className="subtitle">
          Upload an APK or XAPK, pick an analysis depth, and land straight in a static report,
          MobSF's dynamic analyzer, or a live Burp session - fully automated.
        </p>
      </div>

      <div className="status-row">
        <div className="status-chip">
          <span className="chip-label">Emulator</span>
          <span className="chip-value">
            <span className={`chip-dot ${emulatorUp ? 'ok' : 'bad'}`} />
            {status ? (emulatorUp ? 'Running' : 'Not detected') : 'Checking...'}
          </span>
        </div>
        <div className="status-chip">
          <span className="chip-label">MobSF</span>
          <span className="chip-value">
            <span className={`chip-dot ${status?.mobile_pt_status.includes('mobsf') || status?.mobile_pt_status.includes('Up') ? 'ok' : 'bad'}`} />
            {status ? 'See status panel' : 'Checking...'}
          </span>
        </div>
        <div className="status-chip">
          <span className="chip-label">Burp Suite</span>
          <span className="chip-value">
            <span className={`chip-dot ${status?.burp_proxy_listening ? 'ok' : 'bad'}`} />
            {status ? (status.burp_proxy_listening ? 'Proxy up' : 'Not running') : 'Checking...'}
          </span>
        </div>
      </div>

      <div className="cta-card">
        <div>
          <h2>Start a new scan</h2>
          <p>Drag and drop an APK or XAPK to begin.</p>
        </div>
        <button className="cta-button" onClick={() => navigate('/new-scan')}>
          New Scan &rarr;
        </button>
      </div>

      <section className="jobs-card">
        <h3 className="section-heading">Recent jobs</h3>
        {jobs.length === 0 && <p className="subtitle">No jobs yet - start your first scan above.</p>}
        <ul className="job-list">
          {jobs.map((job) => (
            <li key={job.id} className="job-row" onClick={() => navigate(`/jobs/${job.id}`)}>
              <span className={`status-pill status-${job.status.toLowerCase()}`}>{job.status}</span>
              <span className="job-name">{job.original_filename}</span>
              <span className="job-package">{job.package_name ?? ''}</span>
              {job.analysis_mode && <span className="analysis-tag">{job.analysis_mode}</span>}
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}
