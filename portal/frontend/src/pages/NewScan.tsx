import { useRef, useState, type ChangeEvent, type DragEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { api, ApiError, type AnalysisMode, type DeviceTargetType, type Job } from '../api'

const ALLOWED_EXTENSIONS = ['.apk', '.xapk', '.apkm', '.apks']

// Genymotion's default VirtualBox host-only adb address. Varies by installation/VM count,
// but this is the common default - pre-filling it saves re-typing on every scan.
const GENYMOTION_DEFAULT_IP = '192.168.56.101'

interface ModeOption {
  mode: AnalysisMode
  number: string
  title: string
  description: string
  warning?: string
  needsDevice: boolean
}

const MODE_OPTIONS: ModeOption[] = [
  {
    mode: 'sast',
    number: '01',
    title: 'SAST only',
    description: 'Static analysis only, via MobSF. Fast - no emulator or device involved.',
    needsDevice: false,
  },
  {
    mode: 'sast_dast',
    number: '02',
    title: 'SAST + DAST (MobSF)',
    description:
      "Static analysis plus MobSF's own automated dynamic analysis (mobsfy). That built-in DAST requires a genuinely writable /system - only the Genymotion VM target satisfies it. The AVD emulator (AVB/verity bootloop) and a physical device (Magisk's systemless root doesn't remount /system) do not support MobSF's own dynamic report - pick a target next.",
    warning:
      'Restarts adb and reconfigures the target device’s CA trust store, proxy, and Frida instrumentation. Other adb sessions may be briefly disconnected.',
    needsDevice: true,
  },
  {
    mode: 'sast_dast_burp',
    number: '03',
    title: 'SAST + DAST + Burp handoff',
    description:
      'Everything in mode 2 (MobSF’s dynamic report only works against the Genymotion VM target), then hands the app off to Burp Suite for manual pentesting.',
    warning:
      'Also restarts Burp with a new project file - closes whatever Burp project you currently have open (you will be asked to confirm before that happens).',
    needsDevice: true,
  },
]

type Phase = 'idle' | 'uploading' | 'picking-mode' | 'picking-device' | 'starting'
type CheckState = 'idle' | 'checking' | 'ok' | 'error'

export function NewScan() {
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)
  const [phase, setPhase] = useState<Phase>('idle')
  const [dragActive, setDragActive] = useState(false)
  const [fileName, setFileName] = useState('')
  const [progress, setProgress] = useState(0)
  const [job, setJob] = useState<Job | null>(null)
  const [error, setError] = useState<string | null>(null)

  const [selectedMode, setSelectedMode] = useState<AnalysisMode | null>(null)
  const [deviceTargetType, setDeviceTargetType] = useState<DeviceTargetType>('emulator')
  const [deviceIp, setDeviceIp] = useState('')
  const [checkState, setCheckState] = useState<CheckState>('idle')
  const [checkError, setCheckError] = useState<string | null>(null)
  const [checkedSerial, setCheckedSerial] = useState<string | null>(null)
  const [checkedSelection, setCheckedSelection] = useState<string | null>(null)

  function targetNeedsIp(type: DeviceTargetType): boolean {
    return type === 'physical' || type === 'genymotion'
  }

  function validExtension(name: string): boolean {
    const lower = name.toLowerCase()
    return ALLOWED_EXTENSIONS.some((ext) => lower.endsWith(ext))
  }

  async function startUpload(file: File) {
    if (!validExtension(file.name)) {
      setError(`Unsupported file type - expected one of ${ALLOWED_EXTENSIONS.join(', ')}`)
      return
    }
    setError(null)
    setFileName(file.name)
    setProgress(0)
    setPhase('uploading')
    try {
      const createdJob = await api.uploadJob(file, setProgress)
      setJob(createdJob)
      setPhase('picking-mode')
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Upload failed')
      setPhase('idle')
    }
  }

  function handleDrop(event: DragEvent<HTMLDivElement>) {
    event.preventDefault()
    setDragActive(false)
    const file = event.dataTransfer.files?.[0]
    if (file) startUpload(file)
  }

  async function startJob(mode: AnalysisMode, deviceTarget?: { type: DeviceTargetType; ip: string | null }) {
    if (!job) return
    setPhase('starting')
    setError(null)
    try {
      await api.startJob(job.id, mode, deviceTarget)
      navigate(`/jobs/${job.id}`)
    } catch (err: unknown) {
      setError(err instanceof ApiError ? err.message : 'Could not start job')
      setPhase(deviceTarget ? 'picking-device' : 'picking-mode')
    }
  }

  function handleSelectMode(option: ModeOption) {
    if (!option.needsDevice) {
      startJob(option.mode)
      return
    }
    setSelectedMode(option.mode)
    setCheckState('idle')
    setCheckError(null)
    setCheckedSerial(null)
    setCheckedSelection(null)
    setPhase('picking-device')
  }

  function currentSelectionKey(): string {
    return `${deviceTargetType}:${targetNeedsIp(deviceTargetType) ? deviceIp.trim() : ''}`
  }

  function invalidateCheck() {
    setCheckState('idle')
    setCheckError(null)
    setCheckedSerial(null)
    setCheckedSelection(null)
  }

  function handleTargetTypeChange(nextType: DeviceTargetType) {
    setDeviceTargetType(nextType)
    if (nextType === 'genymotion' && !deviceIp.trim()) {
      setDeviceIp(GENYMOTION_DEFAULT_IP)
    }
    invalidateCheck()
  }

  function handleIpChange(event: ChangeEvent<HTMLInputElement>) {
    setDeviceIp(event.target.value)
    invalidateCheck()
  }

  async function handleCheckConnection() {
    if (targetNeedsIp(deviceTargetType) && !deviceIp.trim()) {
      setCheckState('error')
      setCheckError('Enter the device IP first')
      return
    }
    setCheckState('checking')
    setCheckError(null)
    try {
      const result = await api.checkDevice(
        deviceTargetType,
        targetNeedsIp(deviceTargetType) ? deviceIp.trim() : undefined,
      )
      if (result.ok) {
        setCheckState('ok')
        setCheckedSerial(result.serial ?? null)
        setCheckedSelection(currentSelectionKey())
      } else {
        setCheckState('error')
        setCheckError(result.error ?? 'Device check failed')
        setCheckedSelection(null)
      }
    } catch (err: unknown) {
      setCheckState('error')
      setCheckError(err instanceof ApiError ? err.message : 'Device check failed')
      setCheckedSelection(null)
    }
  }

  const checkPassedForSelection = checkState === 'ok' && checkedSelection === currentSelectionKey()

  function handleStartWithDevice() {
    if (!selectedMode || !checkPassedForSelection) return
    startJob(selectedMode, {
      type: deviceTargetType,
      ip: targetNeedsIp(deviceTargetType) ? deviceIp.trim() : null,
    })
  }

  return (
    <div className="page new-scan-page">
      <div className="hero" style={{ textAlign: 'center', paddingTop: 0 }}>
        <h1>New Scan</h1>
        <p className="subtitle" style={{ margin: '0 auto' }}>
          Drop an app below - the upload finishes first, then you choose how deep to go.
        </p>
      </div>

      {(phase === 'idle' || phase === 'uploading') && (
        <div
          className={`dropzone ${dragActive ? 'drag-active' : ''}`}
          onClick={() => phase === 'idle' && inputRef.current?.click()}
          onDragOver={(e) => {
            e.preventDefault()
            if (phase === 'idle') setDragActive(true)
          }}
          onDragLeave={() => setDragActive(false)}
          onDrop={phase === 'idle' ? handleDrop : undefined}
        >
          {phase === 'idle' ? (
            <>
              <div className="dropzone-icon">&#8659;</div>
              <h2>Drag &amp; drop an app here</h2>
              <p className="subtitle">or click to browse</p>
              <div className="dropzone-formats">APK &middot; XAPK &middot; APKM &middot; APKS</div>
            </>
          ) : (
            <>
              <div className="dropzone-icon">&#8634;</div>
              <h2>Uploading...</h2>
              <p className="subtitle">{fileName}</p>
            </>
          )}
          <input
            ref={inputRef}
            type="file"
            accept={ALLOWED_EXTENSIONS.join(',')}
            hidden
            onChange={(e) => {
              const file = e.target.files?.[0]
              e.target.value = ''
              if (file) startUpload(file)
            }}
          />
        </div>
      )}

      {phase === 'uploading' && (
        <div className="upload-progress" style={{ marginTop: '1.25rem' }}>
          <div className="filename">{fileName}</div>
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${progress}%` }} />
          </div>
          <div className="progress-percent">{progress}%</div>
        </div>
      )}

      {phase === 'picking-mode' && job && (
        <div className="mode-picker">
          <h3 className="section-heading" style={{ textAlign: 'center' }}>
            {job.original_filename} uploaded - choose an analysis depth
          </h3>
          <div className="mode-cards">
            {MODE_OPTIONS.map((option) => (
              <button
                key={option.mode}
                className="mode-card"
                onClick={() => handleSelectMode(option)}
              >
                <span className="mode-number">{option.number}</span>
                <h3>{option.title}</h3>
                <p>{option.description}</p>
                {option.warning && <p className="mode-warning">&#9888; {option.warning}</p>}
              </button>
            ))}
          </div>
        </div>
      )}

      {(phase === 'picking-device' || phase === 'starting') && job && selectedMode && (
        <div className="mode-picker">
          <h3 className="section-heading" style={{ textAlign: 'center' }}>
            Choose a target device
          </h3>
          <div className="device-target-card">
            <div className="device-target-toggle" role="group" aria-label="Device target type">
              <button
                type="button"
                className={`device-target-option ${deviceTargetType === 'emulator' ? 'active' : ''}`}
                disabled={phase === 'starting'}
                onClick={() => handleTargetTypeChange('emulator')}
              >
                Emulator (AVD)
              </button>
              <button
                type="button"
                className={`device-target-option ${deviceTargetType === 'physical' ? 'active' : ''}`}
                disabled={phase === 'starting'}
                onClick={() => handleTargetTypeChange('physical')}
              >
                Physical device
              </button>
              <button
                type="button"
                className={`device-target-option ${deviceTargetType === 'genymotion' ? 'active' : ''}`}
                disabled={phase === 'starting'}
                onClick={() => handleTargetTypeChange('genymotion')}
              >
                Genymotion VM
              </button>
            </div>

            {targetNeedsIp(deviceTargetType) && (
              <div className="device-ip-row">
                <label htmlFor="device-ip">Device IP (adb over WiFi)</label>
                <input
                  id="device-ip"
                  type="text"
                  placeholder={
                    deviceTargetType === 'genymotion' ? `${GENYMOTION_DEFAULT_IP}:5555` : '192.168.1.50:5555'
                  }
                  value={deviceIp}
                  disabled={phase === 'starting'}
                  onChange={handleIpChange}
                />
              </div>
            )}

            <div className="device-check-row">
              <button
                type="button"
                className="check-connection-button"
                disabled={checkState === 'checking' || phase === 'starting'}
                onClick={handleCheckConnection}
              >
                {checkState === 'checking' ? 'Checking...' : 'Check connection'}
              </button>

              {checkPassedForSelection && (
                <span className="check-result check-ok">
                  <span className="chip-dot ok" /> Connected{checkedSerial ? ` - ${checkedSerial}` : ''}
                </span>
              )}
              {checkState === 'error' && (
                <span className="check-result check-error">
                  <span className="chip-dot bad" /> {checkError}
                </span>
              )}
            </div>

            <div className="device-target-actions">
              <button
                type="button"
                className="secondary-button"
                disabled={phase === 'starting'}
                onClick={() => {
                  setSelectedMode(null)
                  setPhase('picking-mode')
                }}
              >
                &larr; Back
              </button>
              <button
                type="button"
                className="cta-button"
                disabled={!checkPassedForSelection || phase === 'starting'}
                onClick={handleStartWithDevice}
              >
                {phase === 'starting' ? 'Starting...' : 'Start scan'}
              </button>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="error-text" style={{ marginTop: '1rem' }}>
          {error}
        </div>
      )}
    </div>
  )
}
