import { useEffect, useState } from 'react'
import { Route, Routes, useNavigate } from 'react-router-dom'
import './App.css'
import { api } from './api'
import { Dashboard } from './pages/Dashboard'
import { JobDetail } from './pages/JobDetail'
import { Login } from './pages/Login'
import { NewScan } from './pages/NewScan'

function AppShell({ onLogout }: { onLogout: () => void }) {
  const navigate = useNavigate()
  return (
    <div className="app-shell">
      <header className="app-header">
        <span className="brand" onClick={() => navigate('/')}>
          Mobile PT Lab
        </span>
        <button
          className="logout-button"
          onClick={() => {
            api.logout().finally(onLogout)
          }}
        >
          Log out
        </button>
      </header>
      <main>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/new-scan" element={<NewScan />} />
          <Route path="/jobs/:jobId" element={<JobDetail />} />
        </Routes>
      </main>
    </div>
  )
}

function App() {
  const [authenticated, setAuthenticated] = useState<boolean | null>(null)

  useEffect(() => {
    api
      .listJobs()
      .then(() => setAuthenticated(true))
      .catch(() => setAuthenticated(false))
  }, [])

  if (authenticated === null) return null
  if (!authenticated) return <Login onLoggedIn={() => setAuthenticated(true)} />

  return <AppShell onLogout={() => setAuthenticated(false)} />
}

export default App
